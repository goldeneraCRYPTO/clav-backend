const { Pool } = require('pg');

function makePool(databaseUrl, nodeEnv) {
  return new Pool({
    connectionString: databaseUrl,
    ssl: nodeEnv === 'production' ? { rejectUnauthorized: false } : false,
  });
}

module.exports = { makePool };
