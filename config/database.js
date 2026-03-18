require('dotenv').config();          // ← must be at the very top
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME || 'sentinel_db',
  user: process.env.DB_USER || 'postgres',
  password: String(process.env.DB_PASSWORD),   // ← force string
});

pool.on('connect', () => console.log('✅ PostgreSQL connected'));
pool.on('error', (err) => console.error('❌ DB error:', err));

module.exports = pool;