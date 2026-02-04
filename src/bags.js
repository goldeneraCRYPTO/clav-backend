const axios = require('axios');
const FormData = require('form-data');

const BAGS_API_BASE = 'https://public-api-v2.bags.fm/api/v1';

// Partner (Golden Era)
const BAGS_PARTNER_WALLET = (process.env.BAGS_PARTNER_WALLET || '').trim();
const BAGS_PARTNER_CONFIG = (process.env.BAGS_PARTNER_CONFIG || '').trim();

function mask(s) {
  if (!s) return '';
  if (s.length <= 10) return s;
  return `${s.slice(0, 6)}...${s.slice(-4)}`;
}

function bagsClient(apiKey) {
  return axios.create({
    baseURL: BAGS_API_BASE,
    timeout: 45_000,
    headers: { 'x-api-key': apiKey },
  });
}

async function getFeeShareWallet(client, { provider, username }) {
  const resp = await client.get('/token-launch/fee-share/wallet/v2', {
    params: { provider, username },
  });
  return resp.data?.response?.wallet;
}

async function createTokenInfo(
  client,
  {
    name,
    symbol,
    description,
    imageUrl,
    website,
    twitter,
    telegram,
    metadataUrl,
    imageFileBuffer,
    imageFileName,
  }
) {
  const fd = new FormData();
  if (imageFileBuffer) fd.append('image', imageFileBuffer, imageFileName || 'logo.png');
  if (name) fd.append('name', name);
  if (symbol) fd.append('symbol', symbol);
  if (description) fd.append('description', description);
  if (imageUrl) fd.append('imageUrl', imageUrl);
  if (metadataUrl) fd.append('metadataUrl', metadataUrl);
  if (website) fd.append('website', website);
  if (twitter) fd.append('twitter', twitter);
  if (telegram) fd.append('telegram', telegram);

  const resp = await client.post('/token-launch/create-token-info', fd, {
    headers: fd.getHeaders(),
    maxBodyLength: Infinity,
  });

  const tokenMint = resp.data?.response?.tokenMint;
  const tokenMetadata = resp.data?.response?.tokenMetadata;

  if (!tokenMint || !tokenMetadata) {
    throw new Error(`Unexpected create-token-info response: ${JSON.stringify(resp.data).slice(0, 600)}`);
  }

  return { tokenMint, tokenMetadata, raw: resp.data };
}

async function createFeeShareConfig(client, { payer, baseMint, claimers }) {
  const claimersArray = claimers.map((c) => c.wallet);
  const basisPointsArray = claimers.map((c) => c.bps);

  // ✅ Partner config MUST be attached here
  const payload = {
    payer,
    baseMint,
    claimersArray,
    basisPointsArray,
  };

  if (BAGS_PARTNER_WALLET && BAGS_PARTNER_CONFIG) {
    payload.partner = BAGS_PARTNER_WALLET;
    payload.partnerConfig = BAGS_PARTNER_CONFIG;
  }

  // ✅ Debug (so you SEE in Railway logs that partner is actually sent)
  console.log(
    '[fee-share/config] partner:',
    payload.partner ? mask(payload.partner) : 'missing',
    'partnerConfig:',
    payload.partnerConfig ? mask(payload.partnerConfig) : 'missing'
  );

  const resp = await client.post('/fee-share/config', payload);

  const r = resp.data?.response || resp.data;
  const configKey = r?.configKey || r?.meteoraConfigKey;
  const transactions = r?.transactions || [];

  if (!configKey) {
    throw new Error(`No configKey in fee-share response: ${JSON.stringify(resp.data).slice(0, 600)}`);
  }

  return { configKey, transactions, raw: resp.data };
}

async function createLaunchTx(client, { ipfs, tokenMint, wallet, configKey, initialBuyLamports = 0 }) {
  // ✅ No partner fields here. This endpoint expects the fee-share configKey (from /fee-share/config).
  const payload = {
    ipfs,
    tokenMint,
    wallet,
    initialBuyLamports,
    configKey,
  };

  const resp = await client.post('/token-launch/create-launch-transaction', payload);

  const tx = resp.data?.response?.transaction || resp.data?.response;
  if (!tx || typeof tx !== 'string') {
    throw new Error(`Unexpected create-launch-transaction response: ${JSON.stringify(resp.data).slice(0, 600)}`);
  }

  return { transaction: tx, raw: resp.data };
}

module.exports = {
  bagsClient,
  getFeeShareWallet,
  createTokenInfo,
  createFeeShareConfig,
  createLaunchTx,
};
