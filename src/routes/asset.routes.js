const router = require('express').Router();
const pool = require('../../config/database');
const { verifyToken } = require('../middleware/auth.middleware');

router.use(verifyToken);

router.get('/', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM assets ORDER BY health_score ASC');
  res.json(rows);
});

router.patch('/:id', async (req, res) => {
  const { status, health_score } = req.body;
  const { rows } = await pool.query(
    'UPDATE assets SET status=$1, health_score=$2, last_seen=NOW() WHERE id=$3 RETURNING *',
    [status, health_score, req.params.id]
  );
  res.json(rows[0]);
});

module.exports = router;