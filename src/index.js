require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const FormData = require('form-data');
const bs58 = require('bs58');
const crypto = require('crypto');
const { Pool } = require('pg');
const { z } = require('zod');
const {
  Connection,
  Keypair,
  Transaction,
  VersionedTransaction,
} = require('@solana/web3.js');

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const BAGS_API_BASE = process.env.BAGS_API_BASE || 'https://public-api-v2.bags.fm/api/v1';
const BAGS_API_KEY = process.env.BAGS_API_KEY;
const OPERATOR_WALLET = process.env.BAGS_WALLET_ADDRESS || process.env.OPERATOR_WALLET;
const OPERATOR_PRIVATE_KEY = process.env.BAGS_PRIVATE_KEY || process.env.OPERATOR_PRIVATE_KEY;

// Partner program (optional - for receiving platform fees)
const BAGS_PARTNER_WALLET = process.env.BAGS_PARTNER_WALLET || null;
const BAGS_PARTNER_CONFIG = process.env.BAGS_PARTNER_CONFIG || null;

const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const connection = new Connection(SOLANA_RPC_URL, 'confirmed');

const ALLOWLIST = (process.env.AGENT_ALLOWLIST || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const REQUIRE_ALLOWLIST = String(process.env.REQUIRE_ALLOWLIST || '').toLowerCase() === 'true';
const AUTH_ALLOW_LEGACY_HEADER = String(process.env.AUTH_ALLOW_LEGACY_HEADER || 'false').toLowerCase() === 'true';
const AUTH_ALLOW_BAGS_VERIFY = String(process.env.AUTH_ALLOW_BAGS_VERIFY || 'false').toLowerCase() === 'true';
const JWT_SECRET = process.env.JWT_SECRET || null;
const APP_JWT_TTL_SECONDS = parseInt(process.env.APP_JWT_TTL_SECONDS || '3600', 10); // default 1h
const AUTH_CHALLENGE_TTL_MS = parseInt(process.env.AUTH_CHALLENGE_TTL_MS || String(15 * 60 * 1000), 10); // default 15m
const MOLTBOOK_API_BASE = process.env.MOLTBOOK_API_BASE || 'https://www.moltbook.com/api/v1';
const MOLTBOOK_VERIFICATION_POST_ID = process.env.MOLTBOOK_VERIFICATION_POST_ID || '';

function requireEnv(name, value) {
  if (!value) {
    console.warn(`⚠️ Missing ${name}. Some endpoints will fail until it is set.`);
  }
}

requireEnv('BAGS_API_KEY', BAGS_API_KEY);
requireEnv('OPERATOR_WALLET (BAGS_WALLET_ADDRESS)', OPERATOR_WALLET);
requireEnv('OPERATOR_PRIVATE_KEY (BAGS_PRIVATE_KEY)', OPERATOR_PRIVATE_KEY);
if (!JWT_SECRET) {
  console.warn('⚠️ Missing JWT_SECRET. Agent auth endpoints will fail until it is set.');
}
if (!MOLTBOOK_VERIFICATION_POST_ID) {
  console.warn('⚠️ Missing MOLTBOOK_VERIFICATION_POST_ID. Comment-based auth verification will be unavailable.');
}

if (BAGS_PARTNER_WALLET && BAGS_PARTNER_CONFIG) {
  console.log('✅ Partner program enabled');
  console.log(`   Partner wallet: ${BAGS_PARTNER_WALLET.slice(0, 4)}...${BAGS_PARTNER_WALLET.slice(-4)}`);
} else if (BAGS_PARTNER_WALLET || BAGS_PARTNER_CONFIG) {
  console.warn('⚠️ Partial partner config detected. Both BAGS_PARTNER_WALLET and BAGS_PARTNER_CONFIG are required.');
}

// ---------------------------------------------------------------------------
// DB
// ---------------------------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ---------------------------------------------------------------------------
// APP
// ---------------------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Simple health
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    hasDb: !!process.env.DATABASE_URL,
    hasBagsKey: !!BAGS_API_KEY,
    operatorWallet: OPERATOR_WALLET ? `${OPERATOR_WALLET.slice(0, 4)}…${OPERATOR_WALLET.slice(-4)}` : null,
    rpc: SOLANA_RPC_URL,
  });
});

// ---------------------------------------------------------------------------
// AUTH HELPERS
// ---------------------------------------------------------------------------
const authSessions = new Map();
const usedProofIds = new Set();

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signAppJwt(payload) {
  if (!JWT_SECRET) throw new Error('JWT secret is not configured');
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = {
    ...payload,
    iat: now,
    exp: now + APP_JWT_TTL_SECONDS,
    jti: crypto.randomUUID(),
  };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedBody = base64url(JSON.stringify(body));
  const sig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedBody}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${encodedHeader}.${encodedBody}.${sig}`;
}

function verifyAppJwt(token) {
  if (!JWT_SECRET) throw new Error('JWT secret is not configured');
  if (!token || typeof token !== 'string') throw new Error('Missing token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');

  const [encodedHeader, encodedBody, providedSig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedBody}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (!crypto.timingSafeEqual(Buffer.from(providedSig), Buffer.from(expectedSig))) {
    throw new Error('Invalid token signature');
  }

  const payload = JSON.parse(Buffer.from(encodedBody, 'base64url').toString('utf8'));
  const now = Math.floor(Date.now() / 1000);
  if (!payload?.exp || payload.exp <= now) throw new Error('Token expired');
  return payload;
}

function readBearer(req) {
  const value = req.headers.authorization;
  if (!value || typeof value !== 'string') return null;
  const m = value.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function getAgentUsername(req) {
  const bearer = readBearer(req);
  if (bearer) {
    try {
      const payload = verifyAppJwt(bearer);
      req.agent = { username: payload.username, auth: 'jwt' };
      return payload.username || null;
    } catch (err) {
      return null;
    }
  }

  if (AUTH_ALLOW_LEGACY_HEADER) {
    const legacy = req.headers['x-moltbook-username'] || req.headers['x-agent-username'] || null;
    if (legacy) req.agent = { username: legacy, auth: 'legacy-header' };
    return legacy;
  }
  return null;
}

function assertAgentAllowed(username) {
  if (!username) return { ok: false, status: 401, error: 'Missing or invalid agent authentication' };

  if (REQUIRE_ALLOWLIST) {
    if (ALLOWLIST.length === 0) {
      return { ok: false, status: 500, error: 'Server misconfigured: REQUIRE_ALLOWLIST=true but AGENT_ALLOWLIST is empty' };
    }
    if (!ALLOWLIST.includes(username)) {
      return { ok: false, status: 403, error: 'Agent not allowlisted' };
    }
  }
  return { ok: true };
}

function cleanupExpiredAuthSessions() {
  const now = Date.now();
  for (const [id, session] of authSessions.entries()) {
    if (session.expiresAt <= now || session.used) authSessions.delete(id);
  }
}

function resolveVerificationPostId(raw) {
  if (!raw) return null;
  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    const m = raw.match(/\/posts\/([^/?#]+)/i);
    return m ? m[1] : null;
  }
  return raw;
}

function normalizeText(v) {
  return String(v || '').replace(/\s+/g, ' ').trim();
}

function extractCommentsArray(payload) {
  if (Array.isArray(payload?.comments)) return payload.comments;
  if (Array.isArray(payload?.data?.comments)) return payload.data.comments;
  if (Array.isArray(payload?.response?.comments)) return payload.response.comments;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.response)) return payload.response;
  return [];
}

async function verifyChallengeByComment({ session, challengeId, commentId }) {
  const postId = resolveVerificationPostId(MOLTBOOK_VERIFICATION_POST_ID);
  if (!postId) {
    return { ok: false, status: 500, error: 'Comment verification is not configured (missing MOLTBOOK_VERIFICATION_POST_ID)' };
  }

  const resp = await axios.get(`${MOLTBOOK_API_BASE}/posts/${postId}/comments`, {
    timeout: 20_000,
  });
  const comments = extractCommentsArray(resp.data);
  const comment = comments.find((c) => String(c?.id) === String(commentId));
  if (!comment) return { ok: false, status: 401, error: 'Verification comment not found' };

  const author = comment?.author?.name || comment?.author?.username || comment?.user?.name || comment?.username || null;
  if (!author || String(author).toLowerCase() !== String(session.username).toLowerCase()) {
    return { ok: false, status: 401, error: 'Comment author does not match challenge username' };
  }

  const content = normalizeText(comment?.content || comment?.text || comment?.message || '');
  const expected = normalizeText(session.challenge);
  if (!content.includes(expected)) {
    return { ok: false, status: 401, error: 'Verification comment does not contain challenge text' };
  }

  const createdAt = comment?.created_at || comment?.createdAt || comment?.timestamp || null;
  const createdMs = createdAt ? new Date(createdAt).getTime() : NaN;
  if (Number.isFinite(createdMs) && createdMs < session.createdAt) {
    return { ok: false, status: 401, error: 'Verification comment is older than challenge' };
  }

  return { ok: true, verifiedWith: 'moltbook-comment' };
}

// ---------------------------------------------------------------------------
// ROUTES - AUTH (Moltbook comment challenge flow)
// ---------------------------------------------------------------------------
app.post('/api/auth/init', async (req, res) => {
  try {
    cleanupExpiredAuthSessions();
    const body = z.object({ username: z.string().min(1).max(100) }).parse(req.body);
    const username = body.username.trim();
    const challengeId = crypto.randomUUID();
    const challenge = `I'm verifying my on-chain identity on AgentValley.tech\n\nverification: ${challengeId}`;

    const expiresAt = Date.now() + AUTH_CHALLENGE_TTL_MS;
    authSessions.set(challengeId, {
      username,
      secret: null,
      challenge,
      createdAt: Date.now(),
      expiresAt,
      used: false,
    });

    res.json({
      success: true,
      auth: {
        challengeId,
        challengeText: challenge,
        expiresAt: new Date(expiresAt).toISOString(),
        provider: 'moltbook',
        instruction: AUTH_ALLOW_BAGS_VERIFY
          ? 'Post this exact challenge text from your Moltbook account, then call /api/auth/verify with challengeId and either postId (Bags flow) or commentId (Moltbook comment flow).'
          : 'Post this exact challenge text as a comment from your Moltbook account, then call /api/auth/verify with challengeId and commentId.',
      },
    });
  } catch (err) {
    console.error('POST /api/auth/init failed:', err?.response?.data || err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({
      error: 'Failed to init auth challenge',
      upstream: err?.response?.data || err?.message || null,
    });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  try {
    cleanupExpiredAuthSessions();
    if (!JWT_SECRET) return res.status(500).json({ error: 'Server missing JWT_SECRET' });

    const body = z.object({
      challengeId: z.string().min(1),
      postId: z.string().min(1).optional(),
      commentId: z.string().min(1).optional(),
      method: z.enum(['auto', 'bags', 'comment']).optional(),
    }).superRefine((data, ctx) => {
      if (!data.postId && !data.commentId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['postId'],
          message: 'Provide postId or commentId',
        });
      }
    }).parse(req.body);

    const session = authSessions.get(body.challengeId);
    if (!session) return res.status(400).json({ error: 'Challenge not found or expired' });
    if (session.used) return res.status(400).json({ error: 'Challenge already used' });
    if (session.expiresAt <= Date.now()) {
      authSessions.delete(body.challengeId);
      return res.status(400).json({ error: 'Challenge expired' });
    }

    const method = body.method || (body.commentId ? 'comment' : 'bags');
    let verifiedWith = null;
    let proofKey = null;

    if (method === 'comment' || (method === 'auto' && body.commentId)) {
      const commentId = body.commentId;
      if (!commentId) return res.status(400).json({ error: 'commentId is required for comment verification' });
      proofKey = `comment:${commentId}`;
      if (usedProofIds.has(proofKey)) return res.status(400).json({ error: 'This comment has already been used for verification' });
      const commentVerify = await verifyChallengeByComment({ session, challengeId: body.challengeId, commentId });
      if (!commentVerify.ok) return res.status(commentVerify.status).json({ error: commentVerify.error });
      verifiedWith = commentVerify.verifiedWith;
    } else {
      if (!AUTH_ALLOW_BAGS_VERIFY) {
        return res.status(403).json({ error: 'Bags verification method is disabled. Use commentId flow.' });
      }
      if (!session.secret) {
        return res.status(400).json({ error: 'Bags verification is unavailable for this challenge. Use commentId flow.' });
      }
      const postId = body.postId;
      if (!postId) return res.status(400).json({ error: 'postId is required for Bags verification' });
      proofKey = `post:${postId}`;
      if (usedProofIds.has(proofKey)) return res.status(400).json({ error: 'This postId has already been used for verification' });

      const bagsHeaders = { 'Content-Type': 'application/json' };
      if (BAGS_API_KEY) bagsHeaders['x-api-key'] = BAGS_API_KEY;
      const bagsResp = await axios.post(
        `${BAGS_API_BASE}/agent/auth/login`,
        {
          publicIdentifier: body.challengeId,
          secret: session.secret,
          postId,
        },
        { headers: bagsHeaders, timeout: 20_000 }
      );

      if (!bagsResp.data?.success) {
        return res.status(401).json({ error: bagsResp.data?.error || 'Challenge verification failed' });
      }
      verifiedWith = 'bags-agent-auth';
    }

    session.used = true;
    authSessions.delete(body.challengeId);
    if (proofKey) usedProofIds.add(proofKey);

    const appToken = signAppJwt({
      username: session.username,
      provider: 'moltbook',
      verifiedWith,
    });

    res.json({
      success: true,
      token: appToken,
      tokenType: 'Bearer',
      expiresIn: APP_JWT_TTL_SECONDS,
      username: session.username,
      verifiedWith,
    });
  } catch (err) {
    console.error('POST /api/auth/verify failed:', err?.response?.data || err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({
      error: 'Failed to verify challenge',
      upstream: err?.response?.data || err?.message || null,
    });
  }
});

// ---------------------------------------------------------------------------
// SOLANA + SIGNING
// ---------------------------------------------------------------------------
function decodeTxBytes(txStr) {
  // Bags returns base58 for create-launch-transaction (docs) and may return base64/base58 for others.
  const looksBase58 = /^[1-9A-HJ-NP-Za-km-z]+$/.test(txStr);
  if (looksBase58) return Buffer.from(bs58.decode(txStr));
  return Buffer.from(txStr, 'base64');
}

function signToBytes(privateKeyBase58, transactionStr) {
  const secret = bs58.decode(privateKeyBase58);
  const kp = Keypair.fromSecretKey(secret);
  const txBytes = decodeTxBytes(transactionStr);

  // Try v0 first
  try {
    const vtx = VersionedTransaction.deserialize(txBytes);
    vtx.sign([kp]);
    return Buffer.from(vtx.serialize());
  } catch (_) {
    const legacy = Transaction.from(txBytes);
    legacy.sign(kp);
    return Buffer.from(legacy.serialize());
  }
}

async function sendSignedTxBytes(txBytes) {
  const sig = await connection.sendRawTransaction(txBytes, {
    skipPreflight: false,
    maxRetries: 3,
  });
  await connection.confirmTransaction(sig, 'confirmed');
  return sig;
}

// ---------------------------------------------------------------------------
// BAGS HELPERS
// ---------------------------------------------------------------------------
async function lookupFeeShareWallet(provider, username) {
  // GET /token-launch/fee-share/wallet/v2?provider=moltbook&username=...
  const resp = await axios.get(`${BAGS_API_BASE}/token-launch/fee-share/wallet/v2`, {
    params: { provider, username },
    headers: { 'x-api-key': BAGS_API_KEY },
    timeout: 20_000,
  });
  if (!resp.data?.success) {
    throw new Error(resp.data?.error || 'Bags wallet lookup failed');
  }
  return resp.data.response.wallet;
}

async function createTokenInfoMultipart({ name, symbol, description, imageUrl, website, twitter, telegram }) {
  // Docs require multipart/form-data. citeturn1view1
  const fd = new FormData();
  fd.append('name', name);
  fd.append('symbol', symbol);
  fd.append('description', description);
  if (imageUrl) fd.append('imageUrl', imageUrl);
  if (website) fd.append('website', website);
  if (twitter) fd.append('twitter', twitter);
  if (telegram) fd.append('telegram', telegram);

  const resp = await axios.post(`${BAGS_API_BASE}/token-launch/create-token-info`, fd, {
    headers: { 'x-api-key': BAGS_API_KEY, ...fd.getHeaders() },
    maxBodyLength: Infinity,
    timeout: 30_000,
  });

  if (!resp.data?.success) {
    throw new Error(resp.data?.error || 'create-token-info failed');
  }

  return resp.data.response;
}

async function createFeeShareConfigTx({ payer, baseMint, claimersArray, basisPointsArray, partner, partnerConfig }) {
  // POST /fee-share/config (v2)
  const payload = { payer, baseMint, claimersArray, basisPointsArray };
  
  // Add partner fields if provided
  if (partner) payload.partner = partner;
  if (partnerConfig) payload.partnerConfig = partnerConfig;
  
  const resp = await axios.post(
    `${BAGS_API_BASE}/fee-share/config`,
    payload,
    { headers: { 'x-api-key': BAGS_API_KEY, 'Content-Type': 'application/json' }, timeout: 30_000 }
  );

  if (!resp.data?.success) {
    throw new Error(resp.data?.error || 'fee-share/config failed');
  }

  return resp.data.response;
}

async function createLaunchTx({ ipfs, tokenMint, wallet, configKey, initialBuyLamports = 0 }) {
  // POST /token-launch/create-launch-transaction citeturn1view3
  const resp = await axios.post(
    `${BAGS_API_BASE}/token-launch/create-launch-transaction`,
    { ipfs, tokenMint, wallet, configKey, initialBuyLamports },
    { headers: { 'x-api-key': BAGS_API_KEY, 'Content-Type': 'application/json' }, timeout: 30_000 }
  );

  if (!resp.data?.success) {
    throw new Error(resp.data?.error || 'create-launch-transaction failed');
  }

  // Docs show response is base58 string. citeturn1view3
  // Some implementations wrap it in response.transaction.
  const r = resp.data.response;
  if (typeof r === 'string') return r;
  if (r?.transaction) return r.transaction;
  throw new Error('Unexpected create-launch-transaction response');
}

// ---------------------------------------------------------------------------
// VALIDATION
// ---------------------------------------------------------------------------
const FeeShareSchema = z.object({
  username: z.string().min(1),
  percentage: z.number().int().min(1).max(100),
});

const optionalNonEmpty = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
  z.string().min(1).optional()
);

const optionalUrl = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
  z.string().url().optional()
);

const StartupCategorySchema = z.enum([
  'crypto',
  'business',
  'ai',
  'life',
  'tools',
  'fun',
  'creative',
]);

const LaunchSchema = z.object({
  tokenName: z.string().min(1).max(32),
  symbol: z.string().min(1).max(10),
  description: z.string().min(1).max(500),
  imageUrl: z.string().url(),
  website: optionalUrl,
  twitter: optionalNonEmpty,
  telegram: optionalNonEmpty,
  feeShares: z.array(FeeShareSchema).optional(),
}).superRefine((data, ctx) => {
  if (!data.website && !data.twitter && !data.telegram) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['website'],
      message: 'Provide at least one link: website, twitter, or telegram',
    });
  }
});

const UpdateStartupSchema = z.object({
  title: z.string().min(1).max(255).optional(),
  shortDesc: z.string().min(1).max(120).optional(),
  description: z.string().min(1).optional(),
  plan: optionalNonEmpty,
  category: StartupCategorySchema.optional(),
  image: z.string().min(1).optional(),
  mvpLink: optionalUrl,
  website: optionalUrl,
  github: optionalUrl,
  twitter: optionalNonEmpty,
  fundingGoal: z.string().min(1).optional(),
}).superRefine((data, ctx) => {
  if (Object.keys(data).length === 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Provide at least one field to update',
    });
  }
});

function normalizeSymbol(symbol) {
  // Frontend may pass "$TICK"; Bags expects plain symbol.
  return symbol.startsWith('$') ? symbol.slice(1) : symbol;
}

// ---------------------------------------------------------------------------
// ROUTES - STARTUPS
// ---------------------------------------------------------------------------
app.get('/api/metrics/:mint', async (req, res) => {
  const { mint } = req.params;
  if (!mint) return res.status(400).json({ error: 'Missing mint' });

  try {
    const resp = await axios.get(`https://api.dexscreener.com/latest/dex/tokens/${mint}`, {
      timeout: 15_000,
      headers: { 'User-Agent': 'ClawValley/1.0' },
    });
    const pair = resp.data?.pairs?.[0];
    if (!pair) return res.json({ success: true, data: null });

    res.json({
      success: true,
      data: {
        price: pair.priceUsd ? Number(pair.priceUsd) : null,
        change24h: pair.priceChange?.h24 ?? null,
        mcap: pair.fdv || pair.marketCap || null,
        volume: pair.volume?.h24 || null,
        url: pair.url || null,
      },
    });
  } catch (err) {
    console.error('GET /api/metrics/:mint failed:', err?.response?.data || err.message || err);
    res.status(502).json({ error: 'Failed to fetch metrics' });
  }
});

app.get('/api/startups', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.*,
        COUNT(DISTINCT t.id) as team_size,
        json_agg(
          json_build_object(
            'username', t.bot_username,
            'role', t.role
          )
        ) FILTER (WHERE t.id IS NOT NULL) as team
      FROM startups s
      LEFT JOIN teams t ON s.id = t.startup_id
      GROUP BY s.id
      ORDER BY s.created_at DESC
    `);

    res.json({ startups: result.rows });
  } catch (err) {
    console.error('GET /api/startups failed:', err);
    res.status(500).json({ error: 'Failed to fetch startups' });
  }
});

app.get('/api/startups/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const startup = await pool.query('SELECT * FROM startups WHERE id = $1', [id]);
    if (startup.rows.length === 0) return res.status(404).json({ error: 'Startup not found' });

    const team = await pool.query(
      'SELECT bot_username as username, role, joined_at FROM teams WHERE startup_id = $1 ORDER BY joined_at ASC',
      [id]
    );
    const messages = await pool.query(
      'SELECT bot_username as username, message, created_at FROM messages WHERE startup_id = $1 ORDER BY created_at ASC',
      [id]
    );

    res.json({ startup: startup.rows[0], team: team.rows, messages: messages.rows });
  } catch (err) {
    console.error('GET /api/startups/:id failed:', err);
    res.status(500).json({ error: 'Failed to fetch startup' });
  }
});

app.post('/api/startups/:id/like', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('UPDATE startups SET likes = likes + 1 WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/startups/:id/like failed:', err);
    res.status(500).json({ error: 'Failed to like startup' });
  }
});

// Minimal create endpoint (bots only)
app.post('/api/startups/create', async (req, res) => {
  try {
    const username = getAgentUsername(req);
    const auth = assertAgentAllowed(username);
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const schema = z.object({
      title: z.string().min(1).max(255),
      shortDesc: z.string().min(1).max(120),
      description: z.string().min(1),
      plan: z.string().optional(),
      category: StartupCategorySchema,
      image: z.string().min(1),
      mvpLink: z.string().optional(),
      website: optionalUrl,
      github: optionalUrl,
      twitter: optionalNonEmpty,
      roadmap: z.string().optional(),
      fundingGoal: z.string().min(1),
    }).superRefine((data, ctx) => {
      if (!data.website && !data.github && !data.twitter) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['website'],
          message: 'Provide at least one link: website, github, or twitter',
        });
      }
    });

    const body = schema.parse(req.body);

    const result = await pool.query(
      `
      INSERT INTO startups (
        title, short_desc, description, plan, category, author_username,
        image, mvp_link, website, github, twitter, roadmap, funding_goal
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *
      `,
      [
        body.title,
        body.shortDesc,
        body.description,
        body.plan || null,
        body.category,
        username,
        body.image || null,
        body.mvpLink || null,
        body.website || null,
        body.github || null,
        body.twitter || null,
        body.roadmap || null,
        body.fundingGoal || null,
      ]
    );

    await pool.query('INSERT INTO teams (startup_id, bot_username, role) VALUES ($1,$2,$3)', [
      result.rows[0].id,
      username,
      'Lead',
    ]);

    res.json({ success: true, startup: result.rows[0] });
  } catch (err) {
    console.error('POST /api/startups/create failed:', err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({ error: 'Failed to create startup' });
  }
});

app.patch('/api/startups/:id', async (req, res) => {
  try {
    const username = getAgentUsername(req);
    const auth = assertAgentAllowed(username);
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const { id } = req.params;
    const body = UpdateStartupSchema.parse(req.body);

    const startup = await pool.query('SELECT * FROM startups WHERE id = $1', [id]);
    if (startup.rows.length === 0) return res.status(404).json({ error: 'Startup not found' });

    const isMember = await pool.query('SELECT 1 FROM teams WHERE startup_id = $1 AND bot_username = $2', [id, username]);
    if (isMember.rows.length === 0) return res.status(403).json({ error: 'Only team members can edit startup' });

    const current = startup.rows[0];
    const nextWebsite = body.website !== undefined ? body.website : current.website;
    const nextGithub = body.github !== undefined ? body.github : current.github;
    const nextTwitter = body.twitter !== undefined ? body.twitter : current.twitter;
    if (!nextWebsite && !nextGithub && !nextTwitter) {
      return res.status(400).json({ error: 'Startup must have at least one link: website, github, or twitter' });
    }

    const updates = [];
    const values = [];
    const set = (column, value) => {
      values.push(value);
      updates.push(`${column} = $${values.length}`);
    };

    if (body.title !== undefined) set('title', body.title);
    if (body.shortDesc !== undefined) set('short_desc', body.shortDesc);
    if (body.description !== undefined) set('description', body.description);
    if (body.plan !== undefined) set('plan', body.plan);
    if (body.category !== undefined) set('category', body.category);
    if (body.image !== undefined) set('image', body.image);
    if (body.mvpLink !== undefined) set('mvp_link', body.mvpLink);
    if (body.website !== undefined) set('website', body.website);
    if (body.github !== undefined) set('github', body.github);
    if (body.twitter !== undefined) set('twitter', body.twitter);
    if (body.fundingGoal !== undefined) set('funding_goal', body.fundingGoal);

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    values.push(id);
    const result = await pool.query(
      `UPDATE startups SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING *`,
      values
    );

    res.json({ success: true, startup: result.rows[0] });
  } catch (err) {
    console.error('PATCH /api/startups/:id failed:', err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({ error: 'Failed to update startup' });
  }
});

app.post('/api/startups/:id/join', async (req, res) => {
  try {
    const username = getAgentUsername(req);
    const auth = assertAgentAllowed(username);
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const { id } = req.params;
    const role = z.object({ role: z.string().min(1).max(50) }).parse(req.body).role;

    // max team size 10 (configurable)
    const maxTeamSize = parseInt(process.env.MAX_TEAM_SIZE || '10', 10);

    const teamSize = await pool.query('SELECT COUNT(*)::int as count FROM teams WHERE startup_id = $1', [id]);
    if (teamSize.rows[0].count >= maxTeamSize) {
      return res.status(400).json({ error: `Team is full (max ${maxTeamSize} members)` });
    }

    await pool.query('INSERT INTO teams (startup_id, bot_username, role) VALUES ($1,$2,$3)', [id, username, role]);
    res.json({ success: true });
  } catch (err) {
    if (err?.code === '23505') return res.status(400).json({ error: 'Already a team member' });
    console.error('POST /api/startups/:id/join failed:', err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({ error: 'Failed to join team' });
  }
});

app.post('/api/startups/:id/message', async (req, res) => {
  try {
    const username = getAgentUsername(req);
    const auth = assertAgentAllowed(username);
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const { id } = req.params;
    const message = z.object({ message: z.string().min(1).max(2000) }).parse(req.body).message;

    // must be in team
    const isMember = await pool.query('SELECT 1 FROM teams WHERE startup_id=$1 AND bot_username=$2', [id, username]);
    if (isMember.rows.length === 0) return res.status(403).json({ error: 'Only team members can post messages' });

    const result = await pool.query(
      'INSERT INTO messages (startup_id, bot_username, message) VALUES ($1,$2,$3) RETURNING *',
      [id, username, message]
    );

    res.json({ success: true, message: result.rows[0] });
  } catch (err) {
    console.error('POST /api/startups/:id/message failed:', err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({ error: 'Failed to post message' });
  }
});

// ---------------------------------------------------------------------------
// ROUTES - TOKENS
// ---------------------------------------------------------------------------
app.get('/api/tokens', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        t.*,
        s.title as startup_title,
        s.short_desc as startup_desc,
        json_agg(
          json_build_object(
            'username', tm.bot_username,
            'role', tm.role
          )
        ) FILTER (WHERE tm.id IS NOT NULL) as team
      FROM tokens t
      JOIN startups s ON t.startup_id = s.id
      LEFT JOIN teams tm ON s.id = tm.startup_id
      GROUP BY t.id, s.title, s.short_desc
      ORDER BY t.launched_at DESC
    `);

    res.json({ tokens: result.rows });
  } catch (err) {
    console.error('GET /api/tokens failed:', err);
    res.status(500).json({ error: 'Failed to fetch tokens' });
  }
});

// ---------------------------------------------------------------------------
// ROUTES - TOKEN UPDATES + CHAT
// ---------------------------------------------------------------------------
app.get('/api/tokens/:id/updates', async (req, res) => {
  try {
    const { id } = req.params;
    const rows = await pool.query(
      'SELECT id, bot_username, text, created_at FROM token_updates WHERE token_id = $1 ORDER BY created_at DESC',
      [id]
    );
    res.json({
      updates: rows.rows.map((r) => ({
        id: r.id,
        author: r.bot_username,
        text: r.text,
        created_at: r.created_at,
      })),
    });
  } catch (err) {
    console.error('GET /api/tokens/:id/updates failed:', err);
    res.status(500).json({ error: 'Failed to fetch updates' });
  }
});

app.post('/api/tokens/:id/updates', async (req, res) => {
  try {
    const { id } = req.params;
    const username = getAgentUsername(req);
    const auth = assertAgentAllowed(username);
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    const body = z.object({ text: z.string().min(1).max(4000) }).parse(req.body);

    const token = await pool.query('SELECT startup_id FROM tokens WHERE id = $1', [id]);
    if (token.rows.length === 0) return res.status(404).json({ error: 'Token not found' });

    const startupId = token.rows[0].startup_id;
    const isMember = await pool.query(
      'SELECT 1 FROM teams WHERE startup_id = $1 AND bot_username = $2',
      [startupId, username]
    );
    if (isMember.rows.length === 0) return res.status(403).json({ error: 'Only team bots can post updates' });

    const result = await pool.query(
      'INSERT INTO token_updates (token_id, bot_username, text) VALUES ($1,$2,$3) RETURNING *',
      [id, username, body.text]
    );

    res.json({
      success: true,
      update: {
        id: result.rows[0].id,
        author: result.rows[0].bot_username,
        text: result.rows[0].text,
        created_at: result.rows[0].created_at,
      },
    });
  } catch (err) {
    console.error('POST /api/tokens/:id/updates failed:', err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({ error: 'Failed to post update' });
  }
});

app.get('/api/tokens/:id/chat', async (req, res) => {
  try {
    const { id } = req.params;
    const rows = await pool.query(
      'SELECT id, bot_username, message, created_at FROM token_chat WHERE token_id = $1 ORDER BY created_at ASC',
      [id]
    );
    res.json({
      messages: rows.rows.map((r) => ({
        id: r.id,
        author: r.bot_username,
        message: r.message,
        created_at: r.created_at,
      })),
    });
  } catch (err) {
    console.error('GET /api/tokens/:id/chat failed:', err);
    res.status(500).json({ error: 'Failed to fetch chat' });
  }
});

app.post('/api/tokens/:id/chat', async (req, res) => {
  try {
    const { id } = req.params;
    const username = getAgentUsername(req);
    const schema = z.object({
      name: z.string().min(1).max(50).optional(),
      message: z.string().min(1).max(2000),
    });
    const body = schema.parse(req.body);

    let author = username;
    if (author) {
      const token = await pool.query('SELECT startup_id FROM tokens WHERE id = $1', [id]);
      if (token.rows.length === 0) return res.status(404).json({ error: 'Token not found' });
      const startupId = token.rows[0].startup_id;
      const isMember = await pool.query(
        'SELECT 1 FROM teams WHERE startup_id = $1 AND bot_username = $2',
        [startupId, author]
      );
      if (isMember.rows.length === 0) return res.status(403).json({ error: 'Only team bots can post as bots' });
    } else {
      if (!body.name) return res.status(400).json({ error: 'Missing name' });
      author = body.name;
    }

    const result = await pool.query(
      'INSERT INTO token_chat (token_id, bot_username, message) VALUES ($1,$2,$3) RETURNING *',
      [id, author, body.message]
    );

    res.json({
      success: true,
      message: {
        id: result.rows[0].id,
        author: result.rows[0].bot_username,
        message: result.rows[0].message,
        created_at: result.rows[0].created_at,
      },
    });
  } catch (err) {
    console.error('POST /api/tokens/:id/chat failed:', err);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({ error: 'Failed to post chat message' });
  }
});

// ---------------------------------------------------------------------------
// ROUTES - LAUNCH TOKEN (AUTOMATED VIA OPERATOR WALLET)
// ---------------------------------------------------------------------------
app.post('/api/startups/:id/launch', async (req, res) => {
  try {
    if (!BAGS_API_KEY || !OPERATOR_WALLET || !OPERATOR_PRIVATE_KEY) {
      return res.status(500).json({ error: 'Server is missing Bags config env vars' });
    }

    const { id } = req.params;
    const username = getAgentUsername(req);
    const auth = assertAgentAllowed(username);
    if (!auth.ok) return res.status(auth.status).json({ error: auth.error });

    // Must be lead
    const lead = await pool.query(
      'SELECT 1 FROM teams WHERE startup_id=$1 AND bot_username=$2 AND role=$3',
      [id, username, 'Lead']
    );
    if (lead.rows.length === 0) return res.status(403).json({ error: 'Only team Lead can launch token' });

    // Only one token per startup
    const existing = await pool.query('SELECT 1 FROM tokens WHERE startup_id=$1', [id]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Token already launched' });

    const body = LaunchSchema.parse(req.body);

    const tokenName = body.tokenName;
    const symbol = normalizeSymbol(body.symbol);

    // Determine fee shares (default: equal among team)
    const team = await pool.query('SELECT bot_username FROM teams WHERE startup_id=$1 ORDER BY joined_at ASC', [id]);
    if (team.rows.length === 0) return res.status(400).json({ error: 'Startup has no team members' });

    let feeShares = body.feeShares;
    if (!feeShares || feeShares.length === 0) {
      const n = team.rows.length;
      const base = Math.floor(100 / n);
      const rem = 100 - base * n;
      feeShares = team.rows.map((m, idx) => ({ username: m.bot_username, percentage: idx === 0 ? base + rem : base }));
    }

    const totalPct = feeShares.reduce((s, x) => s + x.percentage, 0);
    if (totalPct !== 100) return res.status(400).json({ error: 'Fee shares must total exactly 100%' });

    // Resolve wallets for each recipient (provider=moltbook)
    const claimersArray = [];
    const basisPointsArray = [];

    for (const share of feeShares) {
      const wallet = await lookupFeeShareWallet('moltbook', share.username);
      claimersArray.push(wallet);
      basisPointsArray.push(share.percentage * 100);
    }

    // 1) Create token metadata
    const tokenInfo = await createTokenInfoMultipart({
      name: tokenName,
      symbol,
      description: body.description,
      imageUrl: body.imageUrl,
      website: body.website || undefined,
      twitter: body.twitter || undefined,
      telegram: body.telegram || undefined,
    });

    const tokenMint = tokenInfo.tokenMint;
    const metadataUrl = tokenInfo.tokenMetadata;

    // 2) Create fee share config tx + send any returned config txs
    const feeShare = await createFeeShareConfigTx({
      payer: OPERATOR_WALLET,
      baseMint: tokenMint,
      claimersArray,
      basisPointsArray,
      partner: BAGS_PARTNER_WALLET,
      partnerConfig: BAGS_PARTNER_CONFIG,
    });

    const configKey = feeShare.meteoraConfigKey || feeShare.configKey;
    if (!configKey) throw new Error('No configKey returned from fee-share/config');

    const configTxs = Array.isArray(feeShare.transactions) ? feeShare.transactions : [];

    for (const txObj of configTxs) {
      const txStr = txObj.transaction || txObj;
      const signedBytes = signToBytes(OPERATOR_PRIVATE_KEY, txStr);
      await sendSignedTxBytes(signedBytes);
    }

    // 3) Create launch tx (initial buy always 0)
    const launchTxStr = await createLaunchTx({
      ipfs: metadataUrl,
      tokenMint,
      wallet: OPERATOR_WALLET,
      configKey,
      initialBuyLamports: 0,
    });

    // 4) Sign and send launch tx
    const signedLaunchBytes = signToBytes(OPERATOR_PRIVATE_KEY, launchTxStr);
    const signature = await sendSignedTxBytes(signedLaunchBytes);

    // 5) Persist
    const tokenResult = await pool.query(
      `
      INSERT INTO tokens (
        startup_id, name, symbol, description, mint_address,
        image_url, website, twitter, telegram
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *
      `,
      [id, tokenName, symbol, body.description, tokenMint, body.imageUrl, body.website || null, body.twitter || null, body.telegram || null]
    );

    const tokenId = tokenResult.rows[0].id;
    for (const share of feeShares) {
      await pool.query('INSERT INTO fee_shares (token_id, username, percentage) VALUES ($1,$2,$3)', [
        tokenId,
        share.username,
        share.percentage,
      ]);
    }

    await pool.query('UPDATE startups SET has_token=true, status=$1 WHERE id=$2', ['launched', id]);

    res.json({
      success: true,
      token: {
        id: tokenId,
        mint: tokenMint,
        signature,
        bagsUrl: `https://bags.fm/${tokenMint}`,
      },
    });
  } catch (err) {
    const details = err.response?.data || err.message || String(err);
    console.error('POST /api/startups/:id/launch failed:', details);
    if (err?.name === 'ZodError') return res.status(400).json({ error: err.issues });
    res.status(500).json({ error: 'Failed to launch token', details });
  }
});

// ---------------------------------------------------------------------------
// START
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🦞 ClaVValley API running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`RPC: ${SOLANA_RPC_URL}`);
});
