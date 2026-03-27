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


// PUBLIC ROUTE (no auth required)
router.post(
  '/analyse',
  upload.single('file'),
  handleUploadError,
  uploadAndAnalyse
);


// Everything below requires JWT
router.use(verifyToken);


// List
router.get('/', listAnalyses);

// Stats
router.get('/stats', requireRole('analyst', 'admin', 'commander'), getStats);

// Get single
router.get('/:id', getAnalysis);

// Delete
router.delete('/:id', requireRole('admin'), deleteAnalysis);

module.exports = router;