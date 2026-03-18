# SENTINEL — MoD Cyber Incident & Safety Portal — Backend

Backend API for the SENTINEL cyber incident and threat intelligence portal.
Built with Node.js, Express, PostgreSQL, and Claude AI.

---

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express.js
- **Database**: PostgreSQL 15+
- **Auth**: JWT (jsonwebtoken) + bcryptjs
- **AI**: Anthropic Claude (threat analysis)
- **Logging**: Winston
- **Validation**: express-validator
- **Security**: helmet, cors, express-rate-limit

---

## Project Structure

```
sentinel-backend/
├── config/
│   └── database.js          # PostgreSQL pool
├── src/
│   ├── server.js             # Express app entry point
│   ├── controllers/
│   │   ├── auth.controller.js
│   │   ├── incident.controller.js
│   │   ├── dashboard.controller.js
│   │   ├── threat.controller.js
│   │   ├── asset.controller.js
│   │   ├── ai.controller.js
│   │   ├── audit.controller.js
│   │   └── user.controller.js
│   ├── middleware/
│   │   ├── auth.middleware.js    # JWT verify, RBAC, clearance
│   │   ├── audit.middleware.js   # Immutable action logging
│   │   └── validate.middleware.js
│   ├── routes/
│   │   ├── auth.routes.js
│   │   ├── incident.routes.js
│   │   ├── dashboard.routes.js
│   │   ├── threat.routes.js
│   │   ├── asset.routes.js
│   │   ├── ai.routes.js
│   │   ├── audit.routes.js
│   │   └── user.routes.js
│   ├── services/
│   │   └── ai.service.js        # Claude AI integration
│   └── utils/
│       └── logger.js            # Winston logger
└── scripts/
    ├── migrate.js               # Database schema creation
    └── seed.js                  # Demo data + default users
```

---

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env with your DB credentials and API keys
```

### 3. Create database
```bash
psql -U postgres -c "CREATE DATABASE sentinel_db;"
```

### 4. Run migrations
```bash
npm run migrate
```

### 5. Seed demo data
```bash
npm run seed
```

### 6. Start server
```bash
npm run dev     # development (nodemon)
npm start       # production
```

Server starts on `http://localhost:5000`

---

## API Reference

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login — returns JWT |
| POST | `/api/auth/logout` | Logout |
| GET  | `/api/auth/me` | Current user profile |
| POST | `/api/auth/change-password` | Change password |

### Incidents
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/incidents` | List incidents (filterable) |
| GET    | `/api/incidents/:id` | Get single incident |
| POST   | `/api/incidents` | Create + trigger AI analysis |
| PATCH  | `/api/incidents/:id` | Update status/assignment |
| DELETE | `/api/incidents/:id` | Delete (admin only) |

**Query params**: `page`, `limit`, `severity`, `status`, `type`, `from`, `to`, `search`

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard/stats` | KPI counts |
| GET | `/api/dashboard/activity-feed` | Recent incidents |
| GET | `/api/dashboard/threat-origins` | Geo map data |
| GET | `/api/dashboard/system-health` | Asset health scores |
| GET | `/api/dashboard/trend` | 7-day incident trend |

### AI
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ai/analyse/:incidentId` | Re-run AI triage |
| GET  | `/api/ai/briefing?period=24h` | Threat intelligence briefing |
| POST | `/api/ai/chat` | Chat with SENTINEL AI |

### Other
- `GET /api/threats` — threat event log
- `POST /api/threats/:id/block` — block a threat
- `GET /api/assets` — monitored assets
- `GET /api/audit` — audit log (admin/commander only)
- `GET /api/users` — user management (admin only)

---

## User Roles

| Role | Clearance | Access |
|------|-----------|--------|
| `admin` | 5 | Full access |
| `commander` | 4 | All ops + audit log |
| `analyst` | 3 | Incidents, AI, assets |
| `operator` | 2 | View + create incidents |
| `viewer` | 1 | Read-only |

---

## Default Credentials (seed data)

| Username | Password | Role |
|----------|----------|------|
| `admin` | `Admin@Sentinel123` | Admin |
| `analyst.patel` | `Analyst@Sentinel123` | Analyst |

**Change these immediately in any real deployment.**

---

## Security Notes

- All routes require JWT authentication
- Passwords hashed with bcrypt (cost factor 12)
- Rate limiting on all endpoints (stricter on `/auth/login`)
- All sensitive actions automatically written to `audit_logs`
- SQL injection prevented via parameterised queries throughout
- Helmet.js sets secure HTTP headers
- SSL enforced for DB connections in production
