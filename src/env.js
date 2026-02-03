const { z } = require('zod');

const schema = z.object({
  NODE_ENV: z.string().optional(),
  PORT: z.string().optional(),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  // Bags
  BAGS_API_KEY: z.string().min(1, 'BAGS_API_KEY is required'),

  // Operator wallet (the Bags account @clavvalley wallet)
  OPERATOR_WALLET_ADDRESS: z.string().min(32, 'OPERATOR_WALLET_ADDRESS is required'),
  OPERATOR_PRIVATE_KEY: z.string().min(40, 'OPERATOR_PRIVATE_KEY is required (base58 secret key)'),

  // Solana
  SOLANA_RPC_URL: z.string().default('https://api.mainnet-beta.solana.com'),

  // Optional
  AGENT_ALLOWLIST: z.string().optional(), // comma-separated usernames
  REQUIRE_ALLOWLIST: z.string().optional(), // 'true' to enforce
});

function loadEnv() {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const msg = parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment:\n${msg}`);
  }

  const env = parsed.data;
  const requireAllowlist = (env.REQUIRE_ALLOWLIST || '').toLowerCase() === 'true';
  const allowlist = new Set(
    (env.AGENT_ALLOWLIST || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  );

  return {
    ...env,
    requireAllowlist,
    allowlist,
    port: Number(env.PORT || 3000)
  };
}

module.exports = { loadEnv };
