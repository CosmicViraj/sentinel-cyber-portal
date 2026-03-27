/**
 * SENTINEL — File Analysis Controller
 *
 * POST /api/files/analyse   — Upload file, run full analysis pipeline, store result
 * GET  /api/files            — List recent analyses
 * GET  /api/files/:id        — Get single analysis by ID
 * GET  /api/files/stats      — Dashboard stats (verdict counts, top threats)
 * DELETE /api/files/:id      — Delete analysis record (admin only)
 */

const fs   = require('fs');
const path = require('path');
const pool = require('../../config/database');
const { analyseFile } = require('../services/fileAnalysis.service');
const logger = require('../utils/logger');
require('dotenv').config();

const THREATS_DIR = path.resolve(
  process.env.UPLOAD_THREATS_DIR || './uploads/confirmed_threats'
);
if (!fs.existsSync(THREATS_DIR)) fs.mkdirSync(THREATS_DIR, { recursive: true });

// ─────────────────────────────────────────────
// POST /api/files/analyse
// ─────────────────────────────────────────────
exports.uploadAndAnalyse = async (req, res) => {
  const file = req.file;

  if (!file) {
    return res.status(400).json({
      error: 'NO_FILE',
      message: 'No file received. Use multipart/form-data with field name "file".',
    });
  }

  logger.info(`File upload received: "${file.originalname}" (${file.size} bytes) by user ${req.user.id}`);

  try {
    // Run three-layer analysis
    const result = await analyseFile(file.path, file.originalname, file.mimetype);

    // Determine quarantine state
    const shouldQuarantine = ['VULNERABLE', 'HONEYTRAP', 'SUSPICIOUS'].includes(result.verdict);
    let quarantinePath = file.path; // default: stays in quarantine dir

    if (['VULNERABLE', 'HONEYTRAP'].includes(result.verdict)) {
      // Move to confirmed_threats — separate from pending quarantine
      const threatFile = path.join(THREATS_DIR, path.basename(file.path));
      fs.renameSync(file.path, threatFile);
      quarantinePath = threatFile;
      logger.warn(`THREAT CONFIRMED — file moved to confirmed_threats: ${file.originalname} → ${result.verdict}`);
    } else if (result.verdict === 'SAFE') {
      // Safe files are still kept but marked
      logger.info(`File marked SAFE: ${file.originalname}`);
    }

    // Persist to database
    const { rows } = await pool.query(
      `INSERT INTO file_analyses (
         incident_id, uploaded_by,
         original_name, stored_name, file_size, mime_type, sha256_hash,
         verdict, risk_score,
         static_flags, virustotal_result, ai_analysis, honeytrap_indicators,
         is_honeytrap, quarantined, quarantine_path
       ) VALUES (
         $1, $2,
         $3, $4, $5, $6, $7,
         $8, $9,
         $10, $11, $12, $13,
         $14, $15, $16
       ) RETURNING *`,
      [
        req.body.incidentId || null,
        req.user.id,
        file.originalname,
        path.basename(file.path),
        result.fileSize,
        file.mimetype,
        result.sha256,
        result.verdict,
        result.riskScore,
        JSON.stringify(result.staticFlags),
        JSON.stringify(result.virusTotalResult),
        JSON.stringify({
          summary:              result.summary,
          vulnerabilityDetails: result.vulnerabilityDetails,
          recommendedAction:    result.recommendedAction,
          targetProfile:        result.targetProfile,
          confidence:           result.confidence,
          iocExtraction:        result.iocExtraction,
          analysisMs:           result.analysisMs,
          entropy:              result.entropy,
        }),
        JSON.stringify(result.honeyTrapIndicators),
        result.isHoneytrap,
        shouldQuarantine,
        quarantinePath,
      ]
    );

    const saved = rows[0];

    // Audit log (write to audit_logs if table exists in your main DB)
    try {
      await pool.query(
        `INSERT INTO audit_logs (user_id, action, entity_type, entity_id, metadata, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          req.user.id,
          'FILE_ANALYSED',
          'file_analysis',
          saved.id,
          JSON.stringify({ originalName: file.originalname, verdict: result.verdict, riskScore: result.riskScore }),
          req.ip,
        ]
      ).catch(() => {}); // Non-fatal if audit_logs doesn't exist yet
    } catch {}

    // Shape the response
    return res.status(201).json({
      success: true,
      message: `Analysis complete — ${result.verdict}`,
      analysis: {
        id:           saved.id,
        fileName:     saved.original_name,
        verdict:      saved.verdict,
        riskScore:    saved.risk_score,
        isHoneytrap:  saved.is_honeytrap,
        isVulnerable: result.isVulnerable,
        confidence:   result.confidence,
        summary:      result.summary,
        vulnerabilityDetails: result.vulnerabilityDetails,
        honeyTrapIndicators:  result.honeyTrapIndicators,
        targetProfile:        result.targetProfile,
        recommendedAction:    result.recommendedAction,
        iocExtraction:        result.iocExtraction,
        staticFlags:          result.staticFlags,
        virusTotal:           result.virusTotalResult,
        sha256:               result.sha256,
        fileSize:             result.fileSize,
        quarantined:          shouldQuarantine,
        createdAt:            saved.created_at,
      },
    });
  } catch (err) {
    logger.error(`Analysis pipeline failed for "${file?.originalname}": ${err.message}`, err);

    // Clean up uploaded file on catastrophic failure
    if (file?.path && fs.existsSync(file.path)) {
      try { fs.unlinkSync(file.path); } catch {}
    }

    return res.status(500).json({
      error: 'ANALYSIS_FAILED',
      message: 'File analysis pipeline encountered an error. File has been removed.',
      detail: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  }
};

// ─────────────────────────────────────────────
// GET /api/files
// ─────────────────────────────────────────────
exports.listAnalyses = async (req, res) => {
  const page    = Math.max(1, parseInt(req.query.page)  || 1);
  const limit   = Math.min(100, parseInt(req.query.limit) || 20);
  const offset  = (page - 1) * limit;
  const verdict = req.query.verdict;   // filter by verdict
  const honey   = req.query.honeytrap; // filter is_honeytrap=true/false

  const conditions = [];
  const params     = [];

  if (verdict) {
    params.push(verdict.toUpperCase());
    conditions.push(`fa.verdict = $${params.length}`);
  }
  if (honey === 'true') conditions.push('fa.is_honeytrap = TRUE');

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  try {
    const [{ rows }, { rows: countRows }] = await Promise.all([
      pool.query(
        `SELECT
           fa.id, fa.original_name, fa.file_size, fa.mime_type, fa.sha256_hash,
           fa.verdict, fa.risk_score, fa.is_honeytrap, fa.quarantined,
           fa.static_flags, fa.honeytrap_indicators,
           fa.ai_analysis->>'summary' AS summary,
           fa.ai_analysis->>'recommendedAction' AS recommended_action,
           fa.created_at,
           u.username AS uploaded_by_username
         FROM file_analyses fa
         LEFT JOIN users u ON u.id = fa.uploaded_by
         ${where}
         ORDER BY fa.created_at DESC
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limit, offset]
      ),
      pool.query(
        `SELECT COUNT(*) FROM file_analyses fa ${where}`,
        params
      ),
    ]);

    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        total: parseInt(countRows[0].count),
        pages: Math.ceil(parseInt(countRows[0].count) / limit),
      },
    });
  } catch (err) {
    logger.error('Failed to list file analyses:', err);
    res.status(500).json({ error: 'DB_ERROR', message: err.message });
  }
};

// ─────────────────────────────────────────────
// GET /api/files/:id
// ─────────────────────────────────────────────
exports.getAnalysis = async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT fa.*, u.username AS uploaded_by_username
       FROM file_analyses fa
       LEFT JOIN users u ON u.id = fa.uploaded_by
       WHERE fa.id = $1`,
      [req.params.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'NOT_FOUND', message: 'Analysis not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    logger.error('Failed to fetch file analysis:', err);
    res.status(500).json({ error: 'DB_ERROR', message: err.message });
  }
};

// ─────────────────────────────────────────────
// GET /api/files/stats
// ─────────────────────────────────────────────
exports.getStats = async (req, res) => {
  try {
    const [verdictCounts, recentThreats, topIocs] = await Promise.all([
      pool.query(`
        SELECT verdict, COUNT(*) AS count
        FROM file_analyses
        WHERE created_at > NOW() - INTERVAL '30 days'
        GROUP BY verdict
      `),
      pool.query(`
        SELECT id, original_name, verdict, risk_score, created_at
        FROM file_analyses
        WHERE verdict IN ('VULNERABLE', 'HONEYTRAP')
        ORDER BY created_at DESC
        LIMIT 5
      `),
      pool.query(`
        SELECT
          jsonb_array_elements_text(ai_analysis->'iocExtraction'->'domains') AS ioc,
          COUNT(*) AS occurrences
        FROM file_analyses
        WHERE created_at > NOW() - INTERVAL '7 days'
          AND ai_analysis->'iocExtraction'->'domains' != 'null'
        GROUP BY ioc
        ORDER BY occurrences DESC
        LIMIT 10
      `),
    ]);

    res.json({
      verdictCounts:  verdictCounts.rows,
      recentThreats:  recentThreats.rows,
      topDomainIocs:  topIocs.rows,
    });
  } catch (err) {
    logger.error('Failed to get file analysis stats:', err);
    res.status(500).json({ error: 'DB_ERROR', message: err.message });
  }
};

// ─────────────────────────────────────────────
// DELETE /api/files/:id  (admin only)
// ─────────────────────────────────────────────
exports.deleteAnalysis = async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM file_analyses WHERE id = $1',
      [req.params.id]
    );
    if (!rows.length) {
      return res.status(404).json({ error: 'NOT_FOUND' });
    }

    const record = rows[0];

    // Delete stored file if it still exists
    if (record.quarantine_path && fs.existsSync(record.quarantine_path)) {
      fs.unlinkSync(record.quarantine_path);
    }

    await pool.query('DELETE FROM file_analyses WHERE id = $1', [req.params.id]);

    logger.warn(`File analysis record deleted: ${record.original_name} by ${req.user.username}`);
    res.json({ success: true, message: 'Analysis record and file deleted' });
  } catch (err) {
    logger.error('Failed to delete file analysis:', err);
    res.status(500).json({ error: 'DB_ERROR', message: err.message });
  }
};
