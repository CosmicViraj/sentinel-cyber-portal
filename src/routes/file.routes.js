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

const { upload, handleUploadError }    = require('../middleware/upload.middleware');
const { verifyToken, requireClearance } = require('../middleware/auth.middleware');
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
  requireClearance(2),
  upload.single('file'),
  handleUploadError,
  uploadAndAnalyse
);

// List analyses — any authenticated user
router.get('/', listAnalyses);

// Stats summary — analyst+ (clearance 3)
router.get('/stats', requireClearance(3), getStats);

// Single analysis — any authenticated user
router.get('/:id', getAnalysis);

// Delete — admin only (clearance 5)
router.delete('/:id', requireClearance(5), deleteAnalysis);

module.exports = router;
