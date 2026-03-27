/**
 * SENTINEL — Upload Middleware
 * Handles multipart file uploads with strict security controls:
 *  - Allowlist of permitted extensions
 *  - Random filename to prevent path traversal
 *  - Size limit (configurable via env)
 *  - MIME type checking (secondary check done in controller via file-type)
 */

const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
require('dotenv').config();

// Directories
const QUARANTINE_DIR = path.resolve(
  process.env.UPLOAD_QUARANTINE_DIR || './uploads/quarantine'
);
if (!fs.existsSync(QUARANTINE_DIR)) {
  fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
}

// Permitted extensions — deliberately conservative for a MoD context
const ALLOWED_EXTENSIONS = new Set([
  '.pdf', '.txt', '.log', '.json', '.xml', '.csv',
  '.doc', '.docx', '.xls', '.xlsx',
  '.pcap', '.pcapng',       // packet captures
  '.eml', '.msg',           // email files
  '.zip', '.tar', '.gz',   // compressed (still scanned)
  '.ps1', '.sh', '.bat',   // scripts (high-interest for analysis)
  '.exe', '.dll',           // binaries (analysis only — never executed)
]);

const MAX_SIZE_BYTES = parseInt(process.env.MAX_FILE_SIZE_MB || '10') * 1024 * 1024;

// Storage: randomised name, flat quarantine directory
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, QUARANTINE_DIR),
  filename: (_req, file, cb) => {
    const rand = crypto.randomBytes(20).toString('hex');
    const ext  = path.extname(file.originalname).toLowerCase();
    // Store with .quarantine suffix so the OS won't accidentally execute it
    cb(null, `${rand}${ext}.quarantine`);
  },
});

// Filter: reject non-allowlisted extensions immediately
const fileFilter = (_req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return cb(
      Object.assign(new Error(`Extension "${ext}" is not permitted for analysis`), {
        code: 'INVALID_EXTENSION',
        status: 400,
      }),
      false
    );
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_SIZE_BYTES,
    files: 1,             // one file per request
    fields: 5,            // allow incidentId + a few metadata fields
  },
});

// Multer error handler — call as middleware after upload.single(...)
function handleUploadError(err, _req, res, next) {
  if (!err) return next();

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: 'FILE_TOO_LARGE',
      message: `File exceeds the ${process.env.MAX_FILE_SIZE_MB || 10} MB limit`,
    });
  }
  if (err.code === 'INVALID_EXTENSION') {
    return res.status(400).json({ error: 'INVALID_EXTENSION', message: err.message });
  }
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({ error: 'UNEXPECTED_FIELD', message: err.message });
  }

  next(err);
}

module.exports = { upload, handleUploadError };
