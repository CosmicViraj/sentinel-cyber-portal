const router = require('express').Router();
const pool = require('../../config/database');
const { verifyToken } = require('../middleware/auth.middleware');

router.use(verifyToken);

router.get('/stats', async (req, res) => {
  const [active, threats, assets, resolved] = await Promise.all([
    pool.query("SELECT COUNT(*) FROM incidents WHERE status='active'"),
    pool.query("SELECT COUNT(*) FROM threat_events WHERE created_at > NOW() - INTERVAL '7 days'"),
    pool.query('SELECT COUNT(*) FROM assets'),
    pool.query("SELECT COUNT(*) FROM incidents WHERE status='resolved'"),
  ]);
  res.json({
    active_incidents: parseInt(active.rows[0].count),
    threats_this_week: parseInt(threats.rows[0].count),
    systems_monitored: parseInt(assets.rows[0].count),
    resolved: parseInt(resolved.rows[0].count),
  });
});

router.get('/activity-feed', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 10');
  res.json(rows);
});

router.get('/system-health', async (req, res) => {
  const { rows } = await pool.query('SELECT name, status, health_score FROM assets ORDER BY health_score ASC');
  res.json(rows);
});

module.exports = router;