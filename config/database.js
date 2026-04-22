require('dotenv').config();
const { Pool } = require('pg');

// ✅ Better check
const isProd = !!process.env.DATABASE_URL;

console.log("ENV CHECK:", {
  NODE_ENV: process.env.NODE_ENV,
  DATABASE_URL: process.env.DATABASE_URL ? "SET" : "NOT SET"
});

const pool = new Pool(
  isProd
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: {
          rejectUnauthorized: false
        },
        // 🔥 IMPORTANT: force IPv4
        family: 4
      }
    : {
        host: 'localhost',
        port: 5432,
        database: 'sentinel_db',
        user: 'postgres',
        password: process.env.DB_PASSWORD
      }
);

pool.on('connect', () => console.log('✅ PostgreSQL connected'));
pool.on('error', (err) => console.error('❌ DB error:', err));

module.exports = pool;