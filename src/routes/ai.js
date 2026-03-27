const express = require('express');
const router = express.Router();
const { GoogleGenerativeAI } = require('@google/generative-ai');

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// 🔹 CHAT API
router.post('/chat', async (req, res) => {
  try {
    const { messages } = req.body;

    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

    const prompt = messages.map(m => `${m.role}: ${m.content}`).join('\n');

    const result = await model.generateContent(prompt);
    const reply = result.response.text();

    res.json({ reply });

  } catch (err) {
    console.error(err);
    res.status(500).json({ reply: "AI failed" });
  }
});

// 🔹 PHISHING SCAN
router.post('/phishing-scan', async (req, res) => {
  try {
    const { url } = req.body;

    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

    const prompt = `Analyse this URL for phishing risk:\n${url}`;

    const result = await model.generateContent(prompt);
    res.json({ result: result.response.text() });

  } catch (err) {
    res.status(500).json({ result: "Error analysing URL" });
  }
});

// 🔹 VULNERABILITY SCAN
router.post('/vuln-scan', async (req, res) => {
  try {
    const { target } = req.body;

    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

    const prompt = `Analyse vulnerabilities for: ${target}`;

    const result = await model.generateContent(prompt);
    res.json({ result: result.response.text() });

  } catch (err) {
    res.status(500).json({ result: "Error analysing target" });
  }
});

// 🔹 BRIEFING
router.get('/briefing', async (req, res) => {
  try {
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

    const prompt = `Generate a cyber threat intelligence briefing`;

    const result = await model.generateContent(prompt);
    res.json({ briefing: result.response.text() });

  } catch (err) {
    res.status(500).json({ briefing: "Error generating briefing" });
  }
});

module.exports = router;