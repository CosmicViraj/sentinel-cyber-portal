require('dotenv').config();
const Groq = require('groq-sdk');
const MODEL = 'llama-3.3-70b-versatile';

function getGroq() {
  return new Groq({ apiKey: process.env.GROQ_API_KEY });
}

exports.chatWithAI = async (messages) => {
  const res = await getGroq().chat.completions.create({
    model: MODEL,
    messages: [
      { role: 'system', content: 'You are SENTINEL AI — a classified military cyber threat intelligence assistant for the Ministry of Defence. Be concise, tactical, and professional.' },
      ...messages
    ],
    max_tokens: 1024
  });
  return res.choices[0].message.content;
};

exports.analyzeIncident = async (incident) => {
  const res = await getGroq().chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `You are a military cyber analyst. Analyze this incident:
Type: ${incident.type}
Severity: ${incident.severity}
Asset: ${incident.affected_asset}
Description: ${incident.description}
Respond with: SEVERITY SCORE (1-10), THREAT ACTOR PROFILE, ATTACK VECTOR, IMMEDIATE ACTIONS, RISK ASSESSMENT.`
    }],
    max_tokens: 1024
  });
  return res.choices[0].message.content;
};

exports.scanPhishing = async (url) => {
  const res = await getGroq().chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `Analyze this URL for phishing indicators: ${url}
Respond with: VERDICT (Safe/Suspicious/Dangerous), CONFIDENCE %, RED FLAGS (bullet list), RECOMMENDATION.`
    }],
    max_tokens: 512
  });
  return res.choices[0].message.content;
};

exports.scanVulnerability = async (target) => {
  const res = await getGroq().chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `As a defensive security advisor for MoD, analyze this system for vulnerabilities: ${target}
Provide: RISK LEVEL, POTENTIAL VULNERABILITIES (CVEs if known), ATTACK SURFACE, HARDENING RECOMMENDATIONS.`
    }],
    max_tokens: 1024
  });
  return res.choices[0].message.content;
};

exports.generateBriefing = async (incidents) => {
  const res = await getGroq().chat.completions.create({
    model: MODEL,
    messages: [{
      role: 'user',
      content: `Generate a tactical threat intelligence briefing for MoD Cyber Command based on these incidents: ${JSON.stringify(incidents.slice(0,5))}. Include: OVERALL THREAT LEVEL, KEY ATTACK PATTERNS, PRIORITY ACTIONS, RECOMMENDED POSTURE.`
    }],
    max_tokens: 1024
  });
  return res.choices[0].message.content;
};