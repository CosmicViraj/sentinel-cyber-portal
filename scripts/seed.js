const pool = require('../config/database');
const bcrypt = require('bcryptjs');

async function seed() {
  const adminHash = await bcrypt.hash('Admin@Sentinel123', 12);
  const analystHash = await bcrypt.hash('Analyst@Sentinel123', 12);

  await pool.query(`
    INSERT INTO users (username, password_hash, full_name, role, clearance_level)
    VALUES 
      ('admin', $1, 'System Administrator', 'admin', 5),
      ('analyst.patel', $2, 'Sgt. R. Patel', 'analyst', 3)
    ON CONFLICT (username) DO NOTHING;
  `, [adminHash, analystHash]);

  await pool.query(`
    INSERT INTO assets (name, type, ip_address, status, health_score) VALUES
      ('NODE-BRAVO-7', 'Server', '10.0.1.7', 'compromised', 34),
      ('VPN-GW-01', 'Gateway', '10.0.0.1', 'warning', 67),
      ('MAIL-SRV-02', 'Mail Server', '10.0.1.2', 'online', 88),
      ('FILE-SRV-04', 'File Server', '10.0.1.4', 'online', 91),
      ('WS-ALPHA-14', 'Workstation', '10.0.2.14', 'online', 95)
    ON CONFLICT DO NOTHING;
  `);

  await pool.query(`
    INSERT INTO incidents (incident_number, type, severity, status, affected_asset, description)
    VALUES
      ('INC-2247', 'Lateral Movement', 'critical', 'active', 'NODE-BRAVO-7', 'Anomalous lateral movement detected'),
      ('INC-2246', 'Phishing Attempt', 'high', 'investigating', 'MAIL-SRV-02', 'Spear phishing targeting cyber wing'),
      ('INC-2245', 'Brute Force', 'high', 'active', 'VPN-GW-01', '847 failed SSH attempts from 185.220.x.x'),
      ('INC-2244', 'Data Exfiltration', 'medium', 'investigating', 'FILE-SRV-04', 'Unusual outbound traffic detected')
    ON CONFLICT DO NOTHING;
  `);

  console.log('✅ Seed data inserted');
  process.exit(0);
}

seed().catch(err => { console.error(err); process.exit(1); });