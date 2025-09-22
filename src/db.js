// src/db.js
const { Pool } = require('pg');
const isProd = process.env.NODE_ENV === 'production';
const sslStrict = (process.env.DB_SSL_STRICT ?? (isProd ? 'true' : 'false')) === 'true';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: sslStrict ? { rejectUnauthorized: true } : { rejectUnauthorized: false },
  max: parseInt(process.env.PGPOOL_MAX || '5', 10),
  idleTimeoutMillis: parseInt(process.env.PG_IDLE_TIMEOUT || '10000', 10),
  connectionTimeoutMillis: parseInt(process.env.PG_CONN_TIMEOUT || '10000', 10),
});

async function ping() {
  const { rows } = await pool.query('select now() as now');
  return rows[0].now;
}
async function query(text, params) { return pool.query(text, params); }

const shutdown = async () => { try { await pool.end(); } catch {} process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

module.exports = { pool, ping, query };