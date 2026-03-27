const express = require('express');
const router = express.Router();
const aiService = require('../services/ai.service');



// 🔹 CHAT API
router.post("/chat", async (req, res) => {
  try {

    const { messages } = req.body;

    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: "Messages array required" });
    }

    const reply = await aiService.chatWithAI(messages);

    res.json({ reply });

  } catch (err) {

    console.error("AI error:", err);
    res.status(500).json({ error: "AI failed" });

  }
});

module.exports = router;

// 🔹 PHISHING SCAN
router.post("/phishing-scan", async (req, res) => {
  try {

    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "URL required" });
    }

    const result = await aiService.scanPhishing(url);

    res.json({ result });

  } catch (err) {

    console.error("Phishing scan error:", err);
    res.status(500).json({ error: "Phishing scan failed" });

  }
});

// 🔹 VULNERABILITY SCAN
router.post("/vuln-scan", async (req, res) => {
  try {

    const { target } = req.body;

    if (!target) {
      return res.status(400).json({ error: "Target required" });
    }

    const result = await aiService.scanVulnerability(target);

    res.json({ result });

  } catch (err) {

    console.error("Vulnerability scan error:", err);
    res.status(500).json({ error: "Vulnerability scan failed" });

  }
});

// 🔹 BRIEFING
router.post("/briefing", async (req, res) => {
  try {

    const { incidents } = req.body;

    if (!incidents) {
      return res.status(400).json({ error: "Incidents required" });
    }

    const briefing = await aiService.generateBriefing(incidents);

    res.json({ briefing });

  } catch (err) {

    console.error("Briefing error:", err);
    res.status(500).json({ error: "Briefing generation failed" });

  }
});

module.exports = router;