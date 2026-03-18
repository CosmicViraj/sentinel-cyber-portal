require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(morgan('dev'));

// Rate limiting
app.use('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));
app.use('/api/', rateLimit({ windowMs: 1 * 60 * 1000, max: 200 }));

// Serve frontend pages
app.use(express.static(path.join(__dirname, '../')));
app.use('/pages', express.static(path.join(__dirname, '../pages')));

// API Routes
app.use('/api/auth', require('./routes/auth.routes'));
app.use('/api/incidents', require('./routes/incident.routes'));
app.use('/api/dashboard', require('./routes/dashboard.routes'));
app.use('/api/ai', require('./routes/ai.routes'));
app.use('/api/assets', require('./routes/asset.routes'));

app.get('/api/health', (req, res) => res.json({ status: 'online', time: new Date() }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SENTINEL running on http://localhost:${PORT}`);
});