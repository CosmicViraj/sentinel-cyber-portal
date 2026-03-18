const router = require('express').Router();
const pool = require('../../config/database');
const { verifyToken } = require('../middleware/auth.middleware');
const aiService = require('../services/ai.service');

router.use(verifyToken);

router.get('/', async (req, res) => {
  const { severity, status, page = 1, limit = 20 } = req.query;
  let query = 'SELECT * FROM incidents WHERE 1=1';
  const params = [];
  if (severity) { params.push(severity); query += ` AND severity=$${params.length}`; }
  if (status) { params.push(status); query += ` AND status=$${params.length}`; }
  query += ` ORDER BY created_at DESC LIMIT ${limit} OFFSET ${(page-1)*limit}`;
  const { rows } = await pool.query(query, params);
  res.json(rows);
});

router.get('/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM incidents WHERE id=$1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
});

router.post('/', async (req, res) => {
  const { type, severity, affected_asset, description } = req.body;
  const num = 'INC-' + Date.now().toString().slice(-4);
  const { rows } = await pool.query(
    `INSERT INTO incidents (incident_number, type, severity, affected_asset, description, reporter_id)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [num, type, severity, affected_asset, description, req.user.id]
  );
  const incident = rows[0];

  // Trigger AI analysis asynchronously
  aiService.analyzeIncident(incident).then(analysis => {
    pool.query('UPDATE incidents SET ai_analysis=$1 WHERE id=$2', [analysis, incident.id]);
  }).catch(console.error);

  res.status(201).json(incident);
});

router.patch('/:id', async (req, res) => {
  const { status } = req.body;
  const { rows } = await pool.query(
    'UPDATE incidents SET status=$1, updated_at=NOW() WHERE id=$2 RETURNING *',
    [status, req.params.id]
  );
  res.json(rows[0]);
});

module.exports = router;