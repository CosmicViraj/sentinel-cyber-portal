const router = require('express').Router();
const pool = require('../../config/database');
const { verifyToken } = require('../middleware/auth.middleware');
const aiService = require('../services/ai.service');

router.use(verifyToken);

router.post('/chat', async (req, res) => {
  try {
    const { messages } = req.body;
    const reply = await aiService.chatWithAI(messages);
    res.json({ reply });
  } catch (err) {
    console.error(err);
    res.status(500).json({ reply: 'SENTINEL AI error: ' + err.message });
  }
});

router.post('/analyse/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM incidents WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Incident not found' });
    const analysis = await aiService.analyzeIncident(rows[0]);
    await pool.query('UPDATE incidents SET ai_analysis=$1 WHERE id=$2', [analysis, req.params.id]);
    res.json({ analysis });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/briefing', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 10');
    const briefing = await aiService.generateBriefing(rows);
    res.json({ briefing });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/phishing-scan', async (req, res) => {
  try {
    const { url } = req.body;
    const result = await aiService.scanPhishing(url);
    res.json({ result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/vuln-scan', async (req, res) => {
  try {
    const { target } = req.body;
    const result = await aiService.scanVulnerability(target);
    res.json({ result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;