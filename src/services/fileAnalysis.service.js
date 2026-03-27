/**
 * SENTINEL — File Analysis Service
 *
 * Three-layer analysis pipeline:
 *   Layer 1: Static analysis  — hashing, extension, embedded pattern scanning
 *   Layer 2: VirusTotal       — known-signature matching (optional, free API)
 *   Layer 3: Claude AI        — deep content analysis + honeytrap detection
 *
 * Results are merged into a single verdict with risk score 0–100.
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios  = require('axios');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const logger = require('../utils/logger');
require('dotenv').config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ─────────────────────────────────────────────
// LAYER 1 — Static Analysis
// ─────────────────────────────────────────────

/**
 * Compute SHA-256, detect suspicious patterns in file content,
 * and flag structural anomalies (double extension, mismatched MIME, etc.)
 */
async function staticAnalysis(filePath, originalName, declaredMime) {
  const buffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const flags  = [];

  // --- Structural checks ---

  // Double/triple extension (e.g. invoice.pdf.exe, report.docx.js)
  const nameParts = originalName.split('.');
  if (nameParts.length > 2) {
    flags.push({
      type: 'DOUBLE_EXTENSION',
      severity: 'HIGH',
      detail: `Filename has ${nameParts.length - 1} extensions: ${originalName}`,
    });
  }

  // MIME type mismatch with extension
  const ext = path.extname(originalName).toLowerCase();
  const mimeExtMap = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.txt': 'text/plain',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.exe': 'application/x-msdownload',
    '.zip': 'application/zip',
  };
  if (mimeExtMap[ext] && declaredMime && !declaredMime.includes(mimeExtMap[ext].split('/')[1])) {
    flags.push({
      type: 'MIME_MISMATCH',
      severity: 'HIGH',
      detail: `Extension "${ext}" but MIME type declared as "${declaredMime}"`,
    });
  }

  // --- Content pattern scanning (first 16KB) ---
  const textSample = buffer.toString('utf8', 0, Math.min(buffer.length, 16384));

  const patterns = [
    // Code execution
    { regex: /powershell\s*(-\w+\s*)*(-enc|-encodedcommand)/i,  label: 'ENCODED_POWERSHELL',       severity: 'CRITICAL' },
    { regex: /powershell|cmd\.exe|wscript|cscript/i,             label: 'SHELL_INVOCATION',         severity: 'HIGH' },
    { regex: /eval\s*\(|exec\s*\(|system\s*\(/i,                 label: 'CODE_EXECUTION_FUNCTION',  severity: 'HIGH' },
    { regex: /base64_decode\s*\(|atob\s*\(/i,                    label: 'BASE64_DECODE',            severity: 'MEDIUM' },

    // Process injection / memory manipulation
    { regex: /CreateRemoteThread|VirtualAlloc|WriteProcessMemory/i, label: 'PROCESS_INJECTION',     severity: 'CRITICAL' },
    { regex: /LoadLibrary|GetProcAddress|NtUnmapViewOfSection/i,    label: 'REFLECTIVE_LOADING',     severity: 'CRITICAL' },

    // Network indicators
    { regex: /\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b/,             label: 'HARDCODED_IP_PORT',        severity: 'MEDIUM' },
    { regex: /https?:\/\/[^\s"']{80,}/i,                          label: 'LONG_OBFUSCATED_URL',     severity: 'MEDIUM' },
    { regex: /\.onion\b/i,                                         label: 'TOR_HIDDEN_SERVICE',      severity: 'HIGH' },

    // Credential harvesting
    { regex: /BEGIN\s+(RSA|EC|PGP)\s+PRIVATE KEY/i,              label: 'EMBEDDED_PRIVATE_KEY',     severity: 'CRITICAL' },
    { regex: /password\s*=\s*["'][^"']{6,}/i,                    label: 'HARDCODED_CREDENTIAL',     severity: 'HIGH' },
    { regex: /api[_-]?key\s*=\s*["'][^"']{10,}/i,               label: 'HARDCODED_API_KEY',        severity: 'HIGH' },

    // Honeytrap / phishing indicators
    { regex: /urgent|immediate\s+action|account\s+(suspended|locked)/i, label: 'URGENCY_LANGUAGE', severity: 'MEDIUM' },
    { regex: /ministry\s+of\s+defence|mod\.gov\.uk|hmrc\.gov\.uk|ncsc\.gov\.uk/i, label: 'GOV_IMPERSONATION', severity: 'HIGH' },
    { regex: /click\s+here\s+to\s+(verify|confirm|update|login)/i, label: 'PHISHING_CTA',          severity: 'HIGH' },
    { regex: /<img[^>]+src=["']https?:\/\/[^"']+["'][^>]*width=["']?1["']?/i, label: 'TRACKING_PIXEL', severity: 'MEDIUM' },
    { regex: /your\s+(account|password|security)\s+(will\s+)?(expire|be\s+disabled)/i, label: 'SOCIAL_ENGINEERING', severity: 'HIGH' },

    // Obfuscation
    { regex: /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){10,}/i,           label: 'HEX_OBFUSCATION',          severity: 'HIGH' },
    { regex: /chr\(\d+\)\s*&\s*chr\(\d+\)/i,                    label: 'CHAR_OBFUSCATION',         severity: 'HIGH' },
  ];

  for (const { regex, label, severity } of patterns) {
    if (regex.test(textSample)) {
      const match = textSample.match(regex);
      flags.push({
        type: label,
        severity,
        detail: match ? `Matched: "${match[0].slice(0, 80)}"` : undefined,
      });
    }
  }

  // File entropy (high entropy = possible encryption/packing)
  const entropy = calculateEntropy(buffer.slice(0, 4096));
  if (entropy > 7.2) {
    flags.push({
      type: 'HIGH_ENTROPY',
      severity: 'MEDIUM',
      detail: `Entropy ${entropy.toFixed(2)}/8.0 — possible packed/encrypted content`,
    });
  }

  // Preliminary score from static flags
  const severityScore = { CRITICAL: 35, HIGH: 20, MEDIUM: 10, LOW: 5 };
  const staticScore = Math.min(
    flags.reduce((acc, f) => acc + (severityScore[f.severity] || 5), 0),
    60
  );

  return { sha256, flags, size: buffer.length, staticScore, entropy };
}

function calculateEntropy(buf) {
  const freq = new Array(256).fill(0);
  for (const byte of buf) freq[byte]++;
  const len = buf.length;
  return freq.reduce((h, f) => {
    if (f === 0) return h;
    const p = f / len;
    return h - p * Math.log2(p);
  }, 0);
}

// ─────────────────────────────────────────────
// LAYER 2 — VirusTotal
// ─────────────────────────────────────────────

async function virusTotalCheck(filePath, sha256) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    logger.info('VirusTotal API key not set — skipping VT check');
    return { skipped: true, reason: 'No API key configured' };
  }

  try {
    // Step 1: Check by hash (no quota cost)
    const hashCheck = await axios.get(
      `https://www.virustotal.com/api/v3/files/${sha256}`,
      {
        headers: { 'x-apikey': apiKey },
        timeout: 10000,
      }
    );

    const attrs = hashCheck.data?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    return {
      skipped: false,
      known: true,
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      undetected: stats.undetected || 0,
      typeLabel:  attrs.type_description || null,
      lastAnalysis: attrs.last_analysis_date || null,
      permalink: `https://www.virustotal.com/gui/file/${sha256}`,
    };
  } catch (err) {
    if (err?.response?.status === 404) {
      // Unknown to VT — attempt upload (uses quota)
      logger.info(`SHA256 ${sha256} not in VirusTotal — file is unknown`);
      return { skipped: false, known: false, malicious: 0, suspicious: 0 };
    }
    logger.error(`VirusTotal API error: ${err.message}`);
    return { skipped: true, reason: `API error: ${err.message}` };
  }
}

// ─────────────────────────────────────────────
// LAYER 3 — Gemini AI Analysis (UPDATED)
// ─────────────────────────────────────────────

async function aiAnalysis(filePath, originalName, staticFlags, vtResult) {
  let fileContent = '';
  let contentNote = '';

  try {
    const raw = fs.readFileSync(filePath);
    fileContent = raw.toString('utf8', 0, Math.min(raw.length, 6000));
    if (raw.length > 6000) {
      contentNote = `[Truncated — full file is ${raw.length} bytes]`;
    }
  } catch {
    fileContent = '[Binary file — cannot display as text]';
    contentNote = 'Binary content only';
  }

  const vtSummary = vtResult?.skipped
    ? 'VirusTotal skipped'
    : vtResult?.known
    ? `VT: ${vtResult.malicious} malicious, ${vtResult.suspicious} suspicious`
    : 'Unknown file (not in VT)';

  const staticSummary = staticFlags.length
    ? staticFlags.map(f => `• [${f.severity}] ${f.type}: ${f.detail || ''}`).join('\n')
    : '• No static flags';

  const prompt = `
You are a senior cybersecurity analyst.

Analyze this file for:
1. Malware / vulnerabilities
2. Honeytrap / phishing intent

Respond ONLY in valid JSON.

FILE:
Name: ${originalName}

STATIC FLAGS:
${staticSummary}

VIRUSTOTAL:
${vtSummary}

CONTENT:
${contentNote}
${fileContent}

Return JSON:
{
  "is_vulnerable": boolean,
  "is_honeytrap": boolean,
  "risk_score": number (0-100),
  "verdict": "SAFE" | "SUSPICIOUS" | "VULNERABLE" | "HONEYTRAP",
  "confidence": "LOW" | "MEDIUM" | "HIGH",
  "summary": "short summary",
  "vulnerability_details": [],
  "honeytrap_indicators": [],
  "target_profile": string | null,
  "recommended_action": string,
  "ioc_extraction": {
    "ips": [],
    "domains": [],
    "hashes": [],
    "urls": []
  }
}
`;

  try {
    const model = genAI.getGenerativeModel({
      model: "gemini-1.5-flash" // 🔥 fast + cheap
    });

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();

    // Clean JSON
    const clean = text
      .replace(/```json/g, '')
      .replace(/```/g, '')
      .trim();

    return JSON.parse(clean);

  } catch (err) {
    logger.error(`Gemini AI analysis failed: ${err.message}`);

    return {
      is_vulnerable: false,
      is_honeytrap: false,
      risk_score: 50,
      verdict: 'SUSPICIOUS',
      confidence: 'LOW',
      summary: 'Gemini analysis failed. Manual review required.',
      vulnerability_details: ['AI unavailable'],
      honeytrap_indicators: [],
      target_profile: null,
      recommended_action: 'QUARANTINE — AI failure',
      ioc_extraction: { ips: [], domains: [], hashes: [], urls: [] },
    };
  }
}
// ─────────────────────────────────────────────
// MAIN ORCHESTRATOR
// ─────────────────────────────────────────────

/**
 * Run the full three-layer analysis pipeline.
 * @param {string} filePath     - Absolute path to the uploaded (quarantined) file
 * @param {string} originalName - Original filename as uploaded by the user
 * @param {string} declaredMime - MIME type as reported by the browser
 * @returns {Object}            - Consolidated analysis result
 */
async function analyseFile(filePath, originalName, declaredMime) {
  logger.info(`Starting analysis: ${originalName}`);
  const startTime = Date.now();

  // Layer 1: Static (fast, always runs)
  const staticResult = await staticAnalysis(filePath, originalName, declaredMime);
  logger.info(`Static analysis done: ${staticResult.flags.length} flags, score ${staticResult.staticScore}`);

  // Layer 2: VirusTotal (async, may be skipped)
  const vtResult = await virusTotalCheck(filePath, staticResult.sha256);
  logger.info(`VirusTotal done: known=${vtResult?.known}, malicious=${vtResult?.malicious || 0}`);

  // Layer 3: Claude AI (always runs — it's the most powerful layer)
  const aiResult = await aiAnalysis(filePath, originalName, staticResult.flags, vtResult);
  logger.info(`AI analysis done: verdict=${aiResult.verdict}, score=${aiResult.risk_score}`);

  // Merge VT score into AI risk score
  let finalScore = aiResult.risk_score;
  if (vtResult && !vtResult.skipped && vtResult.known) {
    const vtBoost = Math.min((vtResult.malicious || 0) * 5 + (vtResult.suspicious || 0) * 2, 30);
    finalScore = Math.min(finalScore + vtBoost, 100);
  }

  // Final verdict (AI verdict wins, but VT can escalate it)
  let finalVerdict = aiResult.verdict;
  if (vtResult?.malicious > 3 && finalVerdict === 'SAFE') finalVerdict = 'SUSPICIOUS';
  if (vtResult?.malicious > 10) finalVerdict = 'VULNERABLE';

  const elapsed = Date.now() - startTime;
  logger.info(`Analysis complete in ${elapsed}ms: ${originalName} → ${finalVerdict} (${finalScore}/100)`);

  return {
    // File identity
    sha256:       staticResult.sha256,
    fileSize:     staticResult.size,
    entropy:      staticResult.entropy,

    // Verdict
    verdict:      finalVerdict,
    riskScore:    finalScore,
    confidence:   aiResult.confidence,
    isVulnerable: aiResult.is_vulnerable,
    isHoneytrap:  aiResult.is_honeytrap,

    // Detailed findings
    staticFlags:          staticResult.flags,
    virusTotalResult:     vtResult,
    summary:              aiResult.summary,
    vulnerabilityDetails: aiResult.vulnerability_details || [],
    honeyTrapIndicators:  aiResult.honeytrap_indicators  || [],
    targetProfile:        aiResult.target_profile,
    recommendedAction:    aiResult.recommended_action,
    iocExtraction:        aiResult.ioc_extraction || {},

    // Meta
    analysisMs: elapsed,
  };
}

module.exports = { analyseFile };
