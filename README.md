# SENTINEL — MoD Cyber Incident & Safety Portal

> AI-powered cyber incident reporting and threat intelligence portal for the Ministry of Defence — featuring real-time threat monitoring, AI-driven incident triage, animated global attack visualization, and secure incident reporting with automated threat assessment.

![SENTINEL Dashboard](https://sentinel-sp7p.onrender.com/index.html)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-sentinel--sp7p.onrender.com-00d4ff?style=flat-square)](https://sentinel-sp7p.onrender.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=flat-square&logo=node.js)](https://nodejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-4169E1?style=flat-square&logo=postgresql)](https://postgresql.org)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

---

## 🖥️ Live Demo

**[https://sentinel-sp7p.onrender.com](https://sentinel-sp7p.onrender.com)**

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin@Sentinel123` | Administrator |
| `analyst.patel` | `Analyst@Sentinel123` | Analyst |

---

## ✨ Features

- **🛡️ Real-time Threat Dashboard** — Live KPI stats, incident feed, animated global attack map
- **🤖 AI Threat Analysis** — Powered by Groq (LLaMA 3.3 70B) for instant incident triage, threat briefings, phishing scans
- **📋 Incident Management** — Full CRUD incident registry with severity classification and status tracking
- **🗺️ Global Threat Map** — Animated canvas visualization of live attack vectors targeting UK infrastructure
- **🔐 JWT Authentication** — Role-based access control with 5 clearance levels
- **📊 Asset Registry** — Monitor 348+ assets with health scores and status tracking
- **📜 Immutable Audit Log** — Full action logging for compliance
- **⚡ Response Protocols** — 12 active security protocols with review tracking
- **💬 AI Chat** — Interactive SENTINEL AI assistant for threat intelligence queries

---

## 🏗️ Tech Stack

| Layer | Technology |
|---|---|
| **Runtime** | Node.js 18+ |
| **Framework** | Express.js |
| **Database** | PostgreSQL 15+ |
| **AI Engine** | Groq SDK (LLaMA 3.3 70B) |
| **Auth** | JWT + bcryptjs |
| **Frontend** | Vanilla HTML/CSS/JS |
| **Deployment** | Render.com |
| **Security** | Helmet, CORS, Rate Limiting |

---

## 📁 Project Structure

```
sentinel-cyber-portal/
├── config/
│   └── database.js              # PostgreSQL connection pool
├── src/
│   ├── server.js                # Express app entry point
│   ├── middleware/
│   │   └── auth.middleware.js   # JWT verification + RBAC
│   ├── routes/
│   │   ├── auth.routes.js       # Login, register, password reset
│   │   ├── incident.routes.js   # Incident CRUD
│   │   ├── dashboard.routes.js  # Stats and activity feed
│   │   ├── ai.routes.js         # AI analysis endpoints
│   │   └── asset.routes.js      # Asset management
│   └── services/
│       └── ai.service.js        # Groq AI integration
├── scripts/
│   ├── migrate.js               # Database schema creation
│   └── seed.js                  # Demo data + default users
├── pages/
│   ├── login.html               # Authentication page
│   ├── incidents.html           # Incident registry
│   ├── ai-chat.html             # AI assistant
│   ├── assets.html              # Asset registry
│   ├── threats.html             # Global threat map
│   ├── protocols.html           # Response protocols
│   ├── audit.html               # Audit log
│   ├── report.html              # Report incident
│   └── settings.html            # System settings
└── index.html                   # Main dashboard
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- PostgreSQL 15+
- Groq API key (free at [console.groq.com](https://console.groq.com))

### 1. Clone the repository

```bash
git clone https://github.com/CosmicViraj/sentinel-cyber-portal.git
cd sentinel-cyber-portal
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
NODE_ENV=development
PORT=5000
JWT_SECRET=your_jwt_secret_here
GROQ_API_KEY=your_groq_api_key_here
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sentinel_db
DB_USER=postgres
DB_PASSWORD=your_password_here
```

### 4. Create database

```bash
psql -U postgres -c "CREATE DATABASE sentinel_db;"
```

### 5. Run migrations

```bash
npm run migrate
```

### 6. Seed demo data

```bash
npm run seed
```

### 7. Start the server

```bash
npm run dev     # Development (with nodemon)
npm start       # Production
```

Visit `http://localhost:5000`

---

## 🌐 Deploy to Render (Free)

1. Fork this repo
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your forked repo
4. Set **Build Command**: `npm install`
5. Set **Start Command**: `node scripts/migrate.js && node src/server.js`
6. Add environment variables from your `.env`
7. Add a free PostgreSQL database on Render and copy connection details

---

## 🔌 API Reference

### Auth
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/login` | Login — returns JWT |
| POST | `/api/auth/register` | Register new user |
| GET | `/api/auth/me` | Current user profile |

### Incidents
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/incidents` | List all incidents |
| POST | `/api/incidents` | Create incident + AI triage |
| PATCH | `/api/incidents/:id` | Update status |

### AI
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/ai/chat` | Chat with SENTINEL AI |
| POST | `/api/ai/analyse/:id` | Re-run AI analysis |
| GET | `/api/ai/briefing` | Threat intelligence briefing |
| POST | `/api/ai/phishing-scan` | Scan URL for phishing |
| POST | `/api/ai/vuln-scan` | Vulnerability assessment |

### Dashboard
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/dashboard/stats` | KPI counts |
| GET | `/api/dashboard/activity-feed` | Recent incidents |
| GET | `/api/dashboard/system-health` | Asset health scores |

---

## 👥 User Roles

| Role | Clearance | Access |
|---|---|---|
| `admin` | 5 | Full access |
| `commander` | 4 | All ops + audit |
| `analyst` | 3 | Incidents, AI, assets |
| `operator` | 2 | View + create incidents |
| `viewer` | 1 | Read-only |

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

### Good First Issues

- [ ] Mobile responsive layout
- [ ] Real-time WebSocket alerts
- [ ] Email notifications for critical incidents
- [ ] Dark/light theme toggle
- [ ] Export incidents to PDF/CSV
- [ ] Two-factor authentication
- [ ] Threat intelligence feed integration

---

## 🔒 Security Notes

- All routes require JWT authentication
- Passwords hashed with bcrypt (cost factor 12)
- Rate limiting on all endpoints
- SQL injection prevented via parameterised queries
- Helmet.js sets secure HTTP headers
- SSL enforced for DB in production

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

## ⚠️ Disclaimer

This is a demonstration/educational project. Not affiliated with or endorsed by the UK Ministry of Defence. Default credentials should be changed immediately in any real deployment.

---

<div align="center">
  Built with ⚡ by <a href="https://github.com/CosmicViraj">CosmicViraj</a> — Star ⭐ if you find it useful!
</div>
