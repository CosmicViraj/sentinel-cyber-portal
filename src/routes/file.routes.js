/**
 * SENTINEL — File Analysis Routes
 *
 * POST   /api/files/analyse        — Upload + analyse (analyst, operator, admin, commander)
 * GET    /api/files                 — List analyses (all authenticated users)
 * GET    /api/files/stats           — Dashboard stats (analyst+)
 * GET    /api/files/:id             — Single analysis detail
 * DELETE /api/files/:id             — Delete record + file (admin only)
 */

const express = require('express');
const router  = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth.middleware');
const { upload, handleUploadError } = require('../middleware/upload.middleware');

const {
  uploadAndAnalyse,
  listAnalyses,
  getAnalysis,
  getStats,
  deleteAnalysis,
} = require('../controllers/file.controller');

// All routes require JWT
router.use(verifyToken);

// Upload & analyse — clearance 2+ (operator and above)
router.post(
  '/analyse',
  requireRole('operator', 'analyst', 'admin', 'commander'),
  upload.single('file'),
  handleUploadError,
  uploadAndAnalyse
);

// List
router.get('/', listAnalyses);

// Stats
router.get('/stats', requireRole('analyst', 'admin', 'commander'), getStats);

// Get single
router.get('/:id', getAnalysis);

// Delete
router.delete('/:id', requireRole('admin'), deleteAnalysis);

module.exports = router;
