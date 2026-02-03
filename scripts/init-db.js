require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

(async () => {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('Missing DATABASE_URL');
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  });

  const schemaPath = path.join(__dirname, '..', 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');

  try {
    await pool.query(sql);
    console.log('✅ DB schema applied');
  } catch (err) {
    console.error('❌ Failed to apply schema:', err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
