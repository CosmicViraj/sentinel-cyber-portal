# Contributing to SENTINEL

Thank you for your interest in contributing to SENTINEL! 🛡️

This document explains how to get involved, what we need help with, and how to submit your work.

---

## 🚀 Quick Start

1. **Fork** the repo on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/sentinel-cyber-portal.git
   cd sentinel-cyber-portal
   ```
3. **Set up** the project following the README
4. **Create a branch** for your feature:
   ```bash
   git checkout -b feat/your-feature-name
   ```
5. **Make your changes**, commit, and push
6. **Open a Pull Request** against the `main` branch

---

## 🎯 What We Need Help With

### 🟢 Good First Issues (Beginner Friendly)

- **Mobile responsive layout** — the dashboard needs to work on smaller screens
- **Loading states** — add spinners/skeletons while API calls are in progress
- **Form validation** — improve client-side validation on all forms
- **Error pages** — create 404 and 500 error pages matching the SENTINEL style
- **Accessibility** — add ARIA labels, keyboard navigation support

### 🟡 Intermediate

- **Real-time alerts** — WebSocket integration for live incident notifications
- **Export functionality** — export incidents to CSV or PDF
- **Search and filter** — improve incident search with more filter options
- **Password strength meter** — on the settings/change password page
- **Session timeout** — auto logout after inactivity

### 🔴 Advanced

- **Two-factor authentication** — TOTP/authenticator app support
- **Email notifications** — send alerts for critical incidents via nodemailer
- **Threat intelligence API** — integrate with real threat feeds (OTX, VirusTotal)
- **WebSocket live map** — real-time threat map updates from backend events
- **Docker support** — add Dockerfile and docker-compose.yml
- **CI/CD pipeline** — GitHub Actions for automated testing and deployment

---

## 📐 Code Style

### JavaScript / Node.js

- Use `async/await` over callbacks or `.then()`
- Use `const` and `let`, never `var`
- Add error handling (`try/catch`) on all async functions
- Keep route handlers lean — logic should be in services where possible

### HTML / CSS

- Match the existing SENTINEL aesthetic — dark military UI
- Use the existing CSS variables (`--accent`, `--surface`, `--border`, etc.)
- Use `Share Tech Mono` for monospace text, `Barlow Condensed` for headings
- Keep it vanilla — no frameworks needed for frontend pages

### Database

- Always use parameterised queries — **never** string interpolation in SQL
- Add comments on complex queries
- Follow existing schema patterns

---

## 🌿 Branch Naming

| Type | Format | Example |
|---|---|---|
| Feature | `feat/description` | `feat/mobile-responsive` |
| Bug fix | `fix/description` | `fix/login-error-message` |
| Docs | `docs/description` | `docs/api-reference` |
| Style | `style/description` | `style/sidebar-spacing` |

---

## ✅ Pull Request Checklist

Before submitting your PR, make sure:

- [ ] Code runs locally without errors
- [ ] UI changes match the SENTINEL aesthetic (dark, military, monospace)
- [ ] No `console.log` statements left in production code
- [ ] No hardcoded credentials or API keys
- [ ] SQL queries use parameterised inputs
- [ ] PR description explains what you changed and why

---

## 🐛 Reporting Bugs

Open a GitHub Issue with:

1. **Title** — short description of the bug
2. **Steps to reproduce** — exact steps to trigger it
3. **Expected behaviour** — what should happen
4. **Actual behaviour** — what actually happens
5. **Screenshots** — if relevant
6. **Environment** — browser, OS, Node version

---

## 💡 Suggesting Features

Open a GitHub Issue with the label `enhancement` and include:

1. **What problem does this solve?**
2. **How would it work?**
3. **Any examples or references?**

---

## 🗺️ Roadmap

Future features planned for SENTINEL:

- [ ] Mobile app (React Native)
- [ ] Real-time WebSocket alerts
- [ ] Email / SMS notifications
- [ ] Two-factor authentication
- [ ] Threat intelligence feed integration (OTX, MISP)
- [ ] Incident timeline view
- [ ] PDF report generation
- [ ] Docker + docker-compose support
- [ ] Unit and integration tests
- [ ] Multi-language support

---

## 💬 Questions?

Open a GitHub Issue or Discussion — we're happy to help you get started.

---

**Thank you for helping make SENTINEL better!** 🛡️
