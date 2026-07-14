# StudyFlow.AI

Real account signup/login (bcrypt + JWT) and real Google Sign-In (Google Identity Services + server-side ID token verification).

## Run in GitHub Codespaces / locally

1. `npm install`
2. `cp .env.example .env` and fill in:
   - `GOOGLE_OAUTH_CLIENT_ID` — from Google Cloud Console (OAuth client, type "Web application")
   - `JWT_SECRET1` — any long random string
3. `npm start`
4. Open the forwarded port (3000) — Codespaces will prompt you to open it in browser.

## Google Sign-In setup

In Google Cloud Console → APIs & Credentials → your OAuth client → "Authorized JavaScript origins", add:
- Your Codespace forwarded URL (e.g. `https://xxxxx-3000.app.github.dev`)
- `http://localhost:3000` (for local testing)

## Structure

- `server.js` — Express backend: signup/login/Google verification/session auth, serves `public/`
- `public/index.html` — full frontend (dark mode default, login-gated content)
- `data/users.json` — created automatically at first run (gitignored)
