# WebShield — MERN Web Application Security Scanner

A runnable **capstone starter implementation**, with React, Express, MongoDB, Redis/BullMQ, Google OAuth, JWT cookie sessions, Docker, a local lab, PDF reporting, CI and basic automated tests.

## Quick start

1. Install Docker Desktop and Docker Compose.
2. Copy `.env.example` to `.env`.
3. Replace `JWT_SECRET` with a long random secret. Example: `openssl rand -hex 32`.
4. Run `docker compose up --build`.
5. Open **http://localhost:8080**.
6. Register with an email and password of at least 8 characters.
7. Scan `http://lab:4000/` (the lab's internal Docker DNS name).

The API, MongoDB, Redis, and lab are **not exposed** on the host. The only published port is the web frontend on 8080.

## Google OAuth setup

Create a Google Cloud OAuth 2.0 **Web application** client.
Add `http://localhost:8080/api/auth/google/callback` as an authorized redirect URI.
Put `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`.
Restart `docker compose up --build`. The Google login link is present but disabled until configured.

For real deployment, use HTTPS and update PUBLIC_URL, callback URI, secure cookies and trusted reverse-proxy settings.

## Features implemented

- Register/login, bcrypt password hashes, Google OAuth (when configured), signed JWT stored in HttpOnly SameSite cookie.
- Scan ownership enforced in API; authorization checkbox; strict target allowlist.
- Asynchronous scan worker via Redis/BullMQ; MongoDB findings and scan history.
- Same-origin bounded crawler (up to 15 pages), passive header, HTTP, and cookie checks.
- React dashboard with polling for scan status; PDF report download.
- Helmet, auth rate limits, JSON body size limit, basic input validation, isolated Docker lab.
- Node test runner, GitHub Actions CI, Docker Compose.

## Syllabus mapping

| Syllabus topic | Implementation |
|---|---|
| Jira | Plan externally in Jira; not part of application source |
| JWT / OAuth | Express JWT cookie auth and Google OAuth |
| Advanced Git | GitHub repo and CI workflow; branch/PR practice is procedural |
| Advanced React | Hooks, conditional UI, API requests, state |
| Maven / pyb | Not appropriate for Node.js; npm is the build tool |
| Jenkins | Not included; GitHub Actions CI supplied instead |
| Kubernetes | Extension checklist only, not implemented deployment |
| JUnit / pyunit | Node built-in tests; JUnit/pyunit not applicable to JavaScript |
| Selenium | Not included; Playwright can be added for end-to-end tests |
| API / microservices | Express API + separate scanner worker |
| HTML/CSS/JS | React client |
| Git/GitHub | Git-ready repository |
| Client/server | React -> Nginx -> Express -> MongoDB/Redis |
| Node/Express | REST API |
| CI/CD | GitHub Actions checks |
| Containerization | Docker Compose |

## Important limitations and security notes

**This is a capstone starter, not a production security scanner.** It implements a small set of passive checks; no SQLi, XSS, authenticated crawling, OWASP-wide coverage, live Socket.IO, or automatic remediation comparison is claimed.

The scanner is deliberately restricted to `SCAN_ALLOWED_HOSTS=lab` to prevent arbitrary requests to internal or public systems. Do not widen the allowlist for public deployment without robust DNS rebinding protection, IP-range enforcement, redirect validation, egress firewalling, and proof of authorization. The lab uses HTTP and intentionally weak headers/cookies for demonstration; do not use it for real credentials.

The auth cookie uses SameSite=Strict and HttpOnly; production needs HTTPS, Secure cookies, CSRF defenses for all state-changing routes, key rotation, account recovery, audit logs, stronger password policy, OAuth state/session review, and security testing. Google OAuth's Passport flow may require further production hardening and careful identity-linking policies.

Redis powers the **job queue and a 5-second TTL scan-list cache**. The cache is invalidated when a scan is created; worker updates become visible after the short TTL. MongoDB is the source of truth.

## Local development without Docker

Requires MongoDB and Redis running. Start `npm install && npm start` in `server` and `npm install && npm run dev` in `client`; Vite development proxy is not configured, so Docker is the recommended run mode.

## Test

`cd server && npm install && npm test`

## Suggested next milestones

1. Add scan status events with Socket.IO and full dashboard charts.
2. Add robust per-target authorization proof and scanner sandboxing.
3. Add Playwright crawler and controlled active tests against lab only.
4. Improve Redis caching with event-driven invalidation and deduplication.
5. Add scan fingerprint comparisons and vulnerability lifecycle.
7. Add Kubernetes manifests and Jenkins pipeline if required by the course.
