const pool = require('../config/database');

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      full_name VARCHAR(100),
      role VARCHAR(20) DEFAULT 'operator',
      clearance_level INT DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      incident_number VARCHAR(20) UNIQUE NOT NULL,
      type VARCHAR(100) NOT NULL,
      severity VARCHAR(20) NOT NULL,
      status VARCHAR(30) DEFAULT 'active',
      affected_asset VARCHAR(100),
      description TEXT,
      reporter_id UUID REFERENCES users(id),
      ai_analysis TEXT,
      ai_severity_score INT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS assets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(100) NOT NULL,
      type VARCHAR(50),
      ip_address VARCHAR(50),
      status VARCHAR(30) DEFAULT 'online',
      health_score INT DEFAULT 100,
      last_seen TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS threat_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      origin_country VARCHAR(100),
      origin_ip VARCHAR(50),
      attack_type VARCHAR(100),
      severity VARCHAR(20),
      blocked BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id),
      action VARCHAR(200),
      target_table VARCHAR(50),
      target_id UUID,
      ip_address VARCHAR(50),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log('✅ All tables created');
  process.exit(0);
}

migrate().catch(err => { console.error(err); process.exit(1); });