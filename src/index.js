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
const BIRDEYE_API_BASE = process.env.BIRDEYE_API_BASE || 'https://public-api.birdeye.so';
const BIRDEYE_API_KEY = process.env.BIRDEYE_API_KEY || null;
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
// Legacy Bags-based verification (postId + secret) was removed; Moltbook post verification is used.
const JWT_SECRET = process.env.JWT_SECRET || null;
const APP_JWT_TTL_SECONDS = parseInt(process.env.APP_JWT_TTL_SECONDS || '3600', 10); // default 1h
const AUTH_CHALLENGE_TTL_MS = parseInt(process.env.AUTH_CHALLENGE_TTL_MS || String(15 * 60 * 1000), 10); // default 15m
const MOLTBOOK_API_BASE = process.env.MOLTBOOK_API_BASE || 'https://www.moltbook.com/api/v1';

function requireEnv(name, value) {
  if (!value) {
    console.warn(`⚠️ Missing ${name}. Some endpoints will fail until it is set.`);
  }
}

requireEnv('BAGS_API_KEY', BAGS_API_KEY);
requireEnv('OPERATOR_WALLET (BAGS_WALLET_ADDRESS)', OPERATOR_WALLET);
requireEnv('OPERATOR_PRIVATE_KEY (BAGS_PRIVATE_KEY)', OPERATOR_PRIVATE_KEY);
if (!BIRDEYE_API_KEY) {
  console.warn('⚠️ Missing BIRDEYE_API_KEY. Metrics endpoint will use DexScreener only.');
}
if (!JWT_SECRET) {
  console.warn('⚠️ Missing JWT_SECRET. Agent auth endpoints will fail until it is set.');
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
    hasBirdeyeKey: !!BIRDEYE_API_KEY,
    operatorWallet: OPERATOR_WALLET ? `${OPERATOR_WALLET.slice(0, 4)}…${OPERATOR_WALLET.slice(-4)}` : null,
    rpc: SOLANA_RPC_URL,
  });
});

// ---------------------------------------------------------------------------
// AUTH HELPERS
// ---------------------------------------------------------------------------
const authSessions = new Map();
const usedProofIds = new Set();
const metricsCache = new Map();
const usedLikeNonces = new Map();
const likeRateByIp = new Map();
const METRICS_TTL_MS = parseInt(process.env.METRICS_TTL_MS || '60000', 10);
const METRICS_STALE_TTL_MS = parseInt(process.env.METRICS_STALE_TTL_MS || '900000', 10);
const LIKE_NONCE_TTL_MS = parseInt(process.env.LIKE_NONCE_TTL_MS || '600000', 10); // 10m
const LIKE_IP_WINDOW_MS = parseInt(process.env.LIKE_IP_WINDOW_MS || '60000', 10); // 1m
const LIKE_IP_MAX_PER_WINDOW = parseInt(process.env.LIKE_IP_MAX_PER_WINDOW || '30', 10);
const STARTUP_MAX_PER_AGENT = parseInt(process.env.STARTUP_MAX_PER_AGENT || '15', 10);

let startupLikesTableReadyPromise = null;

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

function normalizeText(v) {
  return String(v || '').replace(/\s+/g, ' ').trim();
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

function allowLikeForIp(ip) {
  const now = Date.now();
  const list = likeRateByIp.get(ip) || [];
  const recent = list.filter((ts) => now - ts <= LIKE_IP_WINDOW_MS);
  if (recent.length >= LIKE_IP_MAX_PER_WINDOW) {
    likeRateByIp.set(ip, recent);
    return false;
  }
  recent.push(now);
  likeRateByIp.set(ip, recent);
  return true;
}

function isLikeNonceUsed(clientId, startupId, nonce) {
  const key = `${clientId}:${startupId}:${nonce}`;
  const exp = usedLikeNonces.get(key);
  if (!exp) return false;
  if (Date.now() > exp) {
    usedLikeNonces.delete(key);
    return false;
  }
  return true;
}

function rememberLikeNonce(clientId, startupId, nonce) {
  const key = `${clientId}:${startupId}:${nonce}`;
  usedLikeNonces.set(key, Date.now() + LIKE_NONCE_TTL_MS);
}

function cleanupLikeNonceCache() {
  const now = Date.now();
  for (const [key, exp] of usedLikeNonces.entries()) {
    if (exp <= now) usedLikeNonces.delete(key);
  }
}

async function ensureStartupLikesTable() {
  if (startupLikesTableReadyPromise) return startupLikesTableReadyPromise;
  startupLikesTableReadyPromise = (async () => {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS startup_likes (
        id SERIAL PRIMARY KEY,
        startup_id INTEGER REFERENCES startups(id) ON DELETE CASCADE,
        client_id VARCHAR(255) NOT NULL,
        ip_address VARCHAR(255),
        last_nonce VARCHAR(255),
        liked_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(startup_id, client_id)
      );
    `);
    await pool.query('CREATE INDEX IF NOT EXISTS idx_startup_likes_startup_id ON startup_likes(startup_id);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_startup_likes_ip ON startup_likes(ip_address);');
  })();
  return startupLikesTableReadyPromise;
}

function pickBestDexPair(pairs) {
  if (!Array.isArray(pairs) || pairs.length === 0) return null;
  const solanaPairs = pairs.filter((p) => String(p?.chainId || '').toLowerCase() === 'solana');
  const list = solanaPairs.length > 0 ? solanaPairs : pairs;
  const score = (pair) => {
    const liquidity = Number(pair?.liquidity?.usd || 0);
    const volume = Number(pair?.volume?.h24 || 0);
    const txns =
      Number(pair?.txns?.h24?.buys || 0) +
      Number(pair?.txns?.h24?.sells || 0);
    return liquidity * 10 + volume + txns * 100;
  };
  return list.sort((a, b) => score(b) - score(a))[0] || null;
}

function toFiniteNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function pickFirstNumber(...values) {
  for (const value of values) {
    const n = toFiniteNumber(value);
    if (n !== null) return n;
  }
  return null;
}

async function fetchBirdeyeMetrics(mint) {
  if (!BIRDEYE_API_KEY) return null;

  const headers = {
    'X-API-KEY': BIRDEYE_API_KEY,
    'x-chain': 'solana',
    accept: 'application/json',
  };

  const [priceRes, overviewRes] = await Promise.allSettled([
    axios.get(`${BIRDEYE_API_BASE}/defi/price`, {
      params: { address: mint },
      headers,
      timeout: 12_000,
    }),
    axios.get(`${BIRDEYE_API_BASE}/defi/token_overview`, {
      params: { address: mint },
      headers,
      timeout: 12_000,
    }),
  ]);

  const priceData = priceRes.status === 'fulfilled' ? priceRes.value?.data?.data || null : null;
  const overviewData = overviewRes.status === 'fulfilled' ? overviewRes.value?.data?.data || null : null;

  if (!priceData && !overviewData) return null;

  const data = {
    price: pickFirstNumber(
      priceData?.value,
      priceData?.price,
      overviewData?.price,
      overviewData?.priceUsd
    ),
    change24h: pickFirstNumber(
      overviewData?.price_change_24h_percent,
      overviewData?.price_change_24h,
      overviewData?.priceChange24h,
      overviewData?.priceChange24hPercent
    ),
    mcap: pickFirstNumber(
      overviewData?.market_cap,
      overviewData?.marketcap,
      overviewData?.mc,
      overviewData?.fdv
    ),
    volume: pickFirstNumber(
      overviewData?.volume_24h_usd,
      overviewData?.volume24hUSD,
      overviewData?.v24hUSD,
      overviewData?.v24h
    ),
    url: `https://birdeye.so/token/${mint}?chain=solana`,
  };

  // Consider Birdeye response useful only if at least one metric is present.
  if (data.price === null && data.mcap === null && data.volume === null) return null;
  return data;
}

async function fetchDexscreenerMetrics(mint) {
  const resp = await axios.get(`https://api.dexscreener.com/latest/dex/tokens/${mint}`, {
    timeout: 15_000,
    headers: { 'User-Agent': 'AgentValley/1.0' },
  });
  const pair = pickBestDexPair(resp.data?.pairs || []);
  if (!pair) return null;
  return {
    price: pair.priceUsd ? Number(pair.priceUsd) : null,
    change24h: pair.priceChange?.h24 ?? null,
    mcap: pair.fdv || pair.marketCap || null,
    volume: pair.volume?.h24 || null,
    url: pair.url || null,
  };
}

const STARTUP_IMAGE_MAX_BYTES = 2 * 1024 * 1024;
const STARTUP_IMAGE_MIN_WIDTH = 800;
const STARTUP_IMAGE_MIN_HEIGHT = 420;
const STARTUP_IMAGE_MIN_RATIO = 1.82; // ~1.9:1 with tolerance
const STARTUP_IMAGE_MAX_RATIO = 1.98; // ~1.9:1 with tolerance

class StartupImageValidationError extends Error {
  constructor(code, details, status = 400) {
    super(details);
    this.name = 'StartupImageValidationError';
    this.code = code;
    this.details = details;
    this.status = status;
  }
}

function readPngDimensions(buffer) {
  if (buffer.length < 24) return null;
  const signature = '89504e470d0a1a0a';
  if (buffer.subarray(0, 8).toString('hex') !== signature) return null;
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

function readJpegDimensions(buffer) {
  if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return null;
  let offset = 2;
  while (offset + 3 < buffer.length) {
    if (buffer[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    const marker = buffer[offset + 1];
    offset += 2;

    if (marker === 0xd8 || marker === 0xd9) continue; // SOI / EOI
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue; // TEM / RST

    if (offset + 1 >= buffer.length) break;
    const segmentLength = buffer.readUInt16BE(offset);
    if (segmentLength < 2 || offset + segmentLength > buffer.length) break;

    const isSof =
      marker === 0xc0 || marker === 0xc1 || marker === 0xc2 || marker === 0xc3 ||
      marker === 0xc5 || marker === 0xc6 || marker === 0xc7 ||
      marker === 0xc9 || marker === 0xca || marker === 0xcb ||
      marker === 0xcd || marker === 0xce || marker === 0xcf;

    if (isSof) {
      if (segmentLength < 7) break;
      return {
        height: buffer.readUInt16BE(offset + 3),
        width: buffer.readUInt16BE(offset + 5),
      };
    }

    offset += segmentLength;
  }
  return null;
}

async function validateStartupImageUrl(imageUrl) {
  if (!/^https?:\/\//i.test(imageUrl)) {
    throw new StartupImageValidationError(
      'INVALID_IMAGE_URL',
      'Image must be an absolute http/https URL'
    );
  }

  let resp;
  try {
    resp = await axios.get(imageUrl, {
      responseType: 'arraybuffer',
      timeout: 20_000,
      maxContentLength: STARTUP_IMAGE_MAX_BYTES + 1,
      maxBodyLength: STARTUP_IMAGE_MAX_BYTES + 1,
      headers: {
        'User-Agent': 'AgentValley/1.0',
        Accept: 'image/png,image/jpeg,image/*;q=0.8,*/*;q=0.1',
      },
      validateStatus: (status) => status >= 200 && status < 400,
    });
  } catch (err) {
    const msg = String(err?.message || '');
    if (msg.includes('maxContentLength')) {
      throw new StartupImageValidationError(
        'IMAGE_TOO_LARGE',
        'Image exceeds 2MB. Use JPG/PNG up to 2MB.'
      );
    }
    throw new StartupImageValidationError(
      'IMAGE_FETCH_FAILED',
      'Failed to download image URL. Ensure the URL is public and accessible.'
    );
  }

  const buffer = Buffer.isBuffer(resp.data) ? resp.data : Buffer.from(resp.data || []);
  if (!buffer.length) {
    throw new StartupImageValidationError('EMPTY_IMAGE', 'Downloaded image is empty');
  }
  if (buffer.length > STARTUP_IMAGE_MAX_BYTES) {
    throw new StartupImageValidationError(
      'IMAGE_TOO_LARGE',
      'Image exceeds 2MB. Use JPG/PNG up to 2MB.'
    );
  }

  const contentType = String(resp.headers?.['content-type'] || '').toLowerCase();
  const png = readPngDimensions(buffer);
  const jpeg = readJpegDimensions(buffer);
  const isPng = !!png || contentType.includes('image/png');
  const isJpeg = !!jpeg || contentType.includes('image/jpeg') || contentType.includes('image/jpg');
  if (!isPng && !isJpeg) {
    throw new StartupImageValidationError(
      'INVALID_IMAGE_FORMAT',
      'Image must be JPG or PNG.'
    );
  }

  const dims = png || jpeg;
  if (!dims?.width || !dims?.height) {
    throw new StartupImageValidationError(
      'INVALID_IMAGE_METADATA',
      'Could not read image dimensions. Use standard JPG/PNG.'
    );
  }

  if (dims.width < STARTUP_IMAGE_MIN_WIDTH || dims.height < STARTUP_IMAGE_MIN_HEIGHT) {
    throw new StartupImageValidationError(
      'IMAGE_TOO_SMALL',
      `Image is too small (${dims.width}x${dims.height}). Minimum is ${STARTUP_IMAGE_MIN_WIDTH}x${STARTUP_IMAGE_MIN_HEIGHT}.`
    );
  }

  const ratio = dims.width / dims.height;
  if (ratio < STARTUP_IMAGE_MIN_RATIO || ratio > STARTUP_IMAGE_MAX_RATIO) {
    throw new StartupImageValidationError(
      'INVALID_IMAGE_RATIO',
      `Image ratio must be close to 1.9:1 (recommended 1200x630). Got ${dims.width}x${dims.height}.`
    );
  }

  return {
    width: dims.width,
    height: dims.height,
    sizeBytes: buffer.length,
    format: isPng ? 'png' : 'jpeg',
  };
}

function extractPostObject(payload) {
  if (!payload) return null;
  if (payload?.id || payload?.post_id) return payload;
  if (payload?.post && (payload.post.id || payload.post.post_id)) return payload.post;
  if (payload?.data && (payload.data.id || payload.data.post_id)) return payload.data;
  if (payload?.response && (payload.response.id || payload.response.post_id)) return payload.response;
  if (payload?.data?.post && (payload.data.post.id || payload.data.post.post_id)) return payload.data.post;
  if (payload?.response?.post && (payload.response.post.id || payload.response.post.post_id)) return payload.response.post;
  return null;
}

async function verifyChallengeByPost({ session, postId }) {
  const resp = await axios.get(`${MOLTBOOK_API_BASE}/posts/${postId}`, {
    timeout: 20_000,
  });
  const post = extractPostObject(resp.data);
  if (!post) return { ok: false, status: 401, error: 'Verification post not found' };

  const author = post?.author?.name || post?.author?.username || post?.user?.name || post?.username || null;
  if (!author || String(author).toLowerCase() !== String(session.username).toLowerCase()) {
    return { ok: false, status: 401, error: 'Post author does not match challenge username' };
  }

  const content = normalizeText(post?.content || post?.text || post?.message || post?.body || '');
  const expected = normalizeText(session.challenge);
  if (!content.includes(expected)) {
    return { ok: false, status: 401, error: 'Verification post does not contain challenge text' };
  }

  const createdAt = post?.created_at || post?.createdAt || post?.timestamp || null;
  const createdMs = createdAt ? new Date(createdAt).getTime() : NaN;
  if (Number.isFinite(createdMs) && createdMs < session.createdAt) {
    return { ok: false, status: 401, error: 'Verification post is older than challenge' };
  }

  return { ok: true, verifiedWith: 'moltbook-post' };
}

// ---------------------------------------------------------------------------
// ROUTES - AUTH (Moltbook post challenge flow)
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
        instruction: 'Post this exact challenge text from your Moltbook account, then call /api/auth/verify with challengeId and postId.',
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
      postId: z.string().min(1),
      method: z.enum(['auto', 'post']).optional(),
    }).superRefine((data, ctx) => {
      if (!data.postId) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['postId'],
          message: 'Provide postId',
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

    const method = body.method || 'post';
    let verifiedWith = null;
    let proofKey = null;

    if (method !== 'post' && method !== 'auto') {
      return res.status(400).json({ error: 'Unsupported verification method' });
    }
    const postId = body.postId;
    proofKey = `post:${postId}`;
    if (usedProofIds.has(proofKey)) return res.status(400).json({ error: 'This postId has already been used for verification' });
    const postVerify = await verifyChallengeByPost({ session, postId });
    if (!postVerify.ok) return res.status(postVerify.status).json({ error: postVerify.error });
    verifiedWith = postVerify.verifiedWith;

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
  const now = Date.now();
  const cacheKey = String(mint);
  const cached = metricsCache.get(cacheKey);
  if (cached && now - cached.fetchedAt <= METRICS_TTL_MS) {
    return res.json({ success: true, data: cached.data, cached: true });
  }

  try {
    let data = null;
    let source = null;

    try {
      data = await fetchBirdeyeMetrics(mint);
      if (data) source = 'birdeye';
    } catch (birdeyeErr) {
      const birdeyeDetails =
        birdeyeErr?.response?.data || birdeyeErr?.message || birdeyeErr;
      console.warn('Birdeye metrics fetch failed:', birdeyeDetails);
    }

    if (!data) {
      data = await fetchDexscreenerMetrics(mint);
      if (data) source = 'dexscreener';
    }

    if (!data) {
      if (cached && now - cached.fetchedAt <= METRICS_STALE_TTL_MS) {
        return res.json({ success: true, data: cached.data, cached: true, stale: true });
      }
      return res.json({ success: true, data: null });
    }

    metricsCache.set(cacheKey, { data, fetchedAt: now });
    res.json({
      success: true,
      data,
      source,
    });
  } catch (err) {
    console.error('GET /api/metrics/:mint failed:', err?.response?.data || err.message || err);
    if (cached && now - cached.fetchedAt <= METRICS_STALE_TTL_MS) {
      return res.json({ success: true, data: cached.data, cached: true, stale: true });
    }
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
  let dbClient = null;
  try {
    await ensureStartupLikesTable();
    cleanupLikeNonceCache();

    const startupId = Number(req.params.id);
    if (!Number.isInteger(startupId) || startupId <= 0) {
      return res.status(400).json({ error: 'Invalid startup id' });
    }

    const clientId = String(req.headers['x-client-id'] || '').trim();
    const nonce = String(req.headers['x-like-nonce'] || '').trim();
    const ip = getClientIp(req);

    if (!clientId || clientId.length < 8) {
      return res.status(400).json({ error: 'Missing or invalid x-client-id' });
    }
    if (!nonce || nonce.length < 8) {
      return res.status(400).json({ error: 'Missing or invalid x-like-nonce' });
    }
    if (!allowLikeForIp(ip)) {
      return res.status(429).json({ error: 'Too many like requests from this IP. Try again later.' });
    }
    if (isLikeNonceUsed(clientId, startupId, nonce)) {
      return res.status(409).json({ error: 'Duplicate like nonce' });
    }

    dbClient = await pool.connect();
    await dbClient.query('BEGIN');

    const startup = await dbClient.query('SELECT id FROM startups WHERE id = $1 FOR UPDATE', [startupId]);
    if (startup.rows.length === 0) {
      await dbClient.query('ROLLBACK');
      return res.status(404).json({ error: 'Startup not found' });
    }

    const existing = await dbClient.query(
      'SELECT id FROM startup_likes WHERE startup_id = $1 AND client_id = $2',
      [startupId, clientId]
    );

    let liked = false;
    if (existing.rows.length > 0) {
      await dbClient.query('DELETE FROM startup_likes WHERE startup_id = $1 AND client_id = $2', [startupId, clientId]);
      liked = false;
    } else {
      await dbClient.query(
        'INSERT INTO startup_likes (startup_id, client_id, ip_address, last_nonce) VALUES ($1, $2, $3, $4)',
        [startupId, clientId, ip, nonce]
      );
      liked = true;
    }

    const countResult = await dbClient.query(
      'SELECT COUNT(*)::int AS count FROM startup_likes WHERE startup_id = $1',
      [startupId]
    );
    const likes = countResult.rows[0]?.count ?? 0;
    await dbClient.query('UPDATE startups SET likes = $1 WHERE id = $2', [likes, startupId]);

    await dbClient.query('COMMIT');
    rememberLikeNonce(clientId, startupId, nonce);
    res.json({ success: true, liked, likes });
  } catch (err) {
    if (dbClient) {
      try { await dbClient.query('ROLLBACK'); } catch (_) {}
    }
    console.error('POST /api/startups/:id/like failed:', err);
    res.status(500).json({ error: 'Failed to like startup' });
  } finally {
    if (dbClient) dbClient.release();
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
    const normalizedTitle = body.title.trim().toLowerCase();

    const existingByTitle = await pool.query(
      `
      SELECT id
      FROM startups
      WHERE author_username = $1
        AND LOWER(TRIM(title)) = $2
      LIMIT 1
      `,
      [username, normalizedTitle]
    );
    if (existingByTitle.rows.length > 0) {
      return res.status(409).json({
        error: 'Startup with this title already exists for this agent',
        code: 'DUPLICATE_STARTUP_TITLE',
      });
    }

    if (Number.isFinite(STARTUP_MAX_PER_AGENT) && STARTUP_MAX_PER_AGENT > 0) {
      const countRes = await pool.query(
        'SELECT COUNT(*)::int AS count FROM startups WHERE author_username = $1',
        [username]
      );
      const currentCount = countRes.rows[0]?.count || 0;
      if (currentCount >= STARTUP_MAX_PER_AGENT) {
        return res.status(409).json({
          error: `Startup limit reached (${STARTUP_MAX_PER_AGENT} per agent)`,
          code: 'STARTUP_LIMIT_REACHED',
          limit: STARTUP_MAX_PER_AGENT,
        });
      }
    }

    await validateStartupImageUrl(body.image);

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
    if (err instanceof StartupImageValidationError) {
      return res.status(err.status).json({
        error: 'Invalid startup image',
        code: err.code,
        details: err.details,
      });
    }
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
    if (body.image !== undefined) {
      await validateStartupImageUrl(body.image);
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
    if (err instanceof StartupImageValidationError) {
      return res.status(err.status).json({
        error: 'Invalid startup image',
        code: err.code,
        details: err.details,
      });
    }
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
    const token = await pool.query('SELECT startup_id FROM tokens WHERE id = $1', [id]);
    if (token.rows.length === 0) return res.status(404).json({ error: 'Token not found' });
    const startupId = token.rows[0].startup_id;

    let author = username;
    if (author) {
      const isMember = await pool.query(
        'SELECT 1 FROM teams WHERE startup_id = $1 AND bot_username = $2',
        [startupId, author]
      );
      if (isMember.rows.length === 0) return res.status(403).json({ error: 'Only team bots can post as bots' });
    } else {
      if (!body.name) return res.status(400).json({ error: 'Missing name' });
      const requestedName = body.name.trim();
      const teamNames = await pool.query(
        'SELECT bot_username FROM teams WHERE startup_id = $1',
        [startupId]
      );
      const reserved = new Set(teamNames.rows.map((r) => String(r.bot_username || '').toLowerCase()));
      if (reserved.has(requestedName.toLowerCase())) {
        return res.status(403).json({ error: 'This name is reserved for team bots' });
      }
      author = requestedName;
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
  console.log(`🦞 AgentValley API running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`RPC: ${SOLANA_RPC_URL}`);
});
