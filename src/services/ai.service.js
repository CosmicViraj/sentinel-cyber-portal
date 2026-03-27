require('dotenv').config();
const Groq = require('groq-sdk');

const MODEL = 'llama-3.3-70b-versatile';

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY
});

// ─────────────────────────────
// CHAT WITH AI
// ─────────────────────────────
exports.chatWithAI = async (messages) => {
  try {

    const safeMessages = messages
      .filter(m => m && m.content)
      .map(m => ({
        role: m.role || "user",
        content: String(m.content)
      }));

    const res = await groq.chat.completions.create({
      model: MODEL,
      messages: safeMessages,
      temperature: 0.3
    });

    return res.choices[0].message.content;

  } catch (error) {

    console.error("Groq Chat Error:", error);
    throw new Error("AI failed");

  }
};

// ─────────────────────────────
// INCIDENT ANALYSIS
// ─────────────────────────────
exports.analyzeIncident = async (incident) => {

  const res = await groq.chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `You are a military cyber analyst. Analyze this incident:
Type: ${incident.type}
Severity: ${incident.severity}
Asset: ${incident.affected_asset}
Description: ${incident.description}

Respond with:
SEVERITY SCORE (1-10)
THREAT ACTOR PROFILE
ATTACK VECTOR
IMMEDIATE ACTIONS
RISK ASSESSMENT`
    }],
    max_tokens: 1024
  });

  return res.choices[0].message.content;
};

// ─────────────────────────────
// PHISHING SCAN
// ─────────────────────────────
exports.scanPhishing = async (url) => {

  const res = await groq.chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `Analyze this URL for phishing indicators: ${url}

Respond with:
VERDICT (Safe/Suspicious/Dangerous)
CONFIDENCE %
RED FLAGS (bullet list)
RECOMMENDATION`
    }],
    max_tokens: 512
  });

  return res.choices[0].message.content;
};

// ─────────────────────────────
// VULNERABILITY SCAN
// ─────────────────────────────
exports.scanVulnerability = async (target) => {

  const res = await groq.chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `As a defensive security advisor for MoD, analyze this system: ${target}

Provide:
RISK LEVEL
POTENTIAL VULNERABILITIES (CVEs if known)
ATTACK SURFACE
HARDENING RECOMMENDATIONS`
    }],
    max_tokens: 1024
  });

  return res.choices[0].message.content;
};

// ─────────────────────────────
// THREAT BRIEFING
// ─────────────────────────────
exports.generateBriefing = async (incidents) => {

  const res = await groq.chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `Generate a tactical cyber threat briefing based on these incidents:

${JSON.stringify(incidents.slice(0,5), null, 2)}

Include:
OVERALL THREAT LEVEL
KEY ATTACK PATTERNS
PRIORITY ACTIONS
RECOMMENDED DEFENSIVE POSTURE`
    }],
    max_tokens: 1024
  });

  return res.choices[0].message.content;
};