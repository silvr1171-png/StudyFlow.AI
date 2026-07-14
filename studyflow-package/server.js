/**
 * StudyFlow.AI backend
 * — Real account signup/login (bcrypt-hashed passwords, JSON file storage)
 * — Real Google Sign-In verification (Google Identity Services ID token)
 * — Serves the static frontend from ./public
 *
 * Run:
 *   npm install
 *   npm start
 * Then open http://localhost:3000
 */
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

// --- tiny .env loader (no extra dependency) ---
(function loadEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if (!(key in process.env)) process.env[key] = value;
  }
})();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET1 || process.env.JWT_SECRET || 'dev-secret-change-me';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_OAUTH_CLIENT_ID || '';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { return []; }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function findUserByEmail(email) {
  return readUsers().find(u => u.email.toLowerCase() === String(email).toLowerCase());
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, year: u.year || '', subjects: u.subjects || '', provider: u.provider || 'password' };
}
function issueToken(u) {
  return jwt.sign({ sub: u.id, email: u.email }, JWT_SECRET, { expiresIn: '30d' });
}

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const app = express();
app.use(cors());
app.use(express.json());

// Expose only the public Client ID to the frontend (never secrets)
app.get('/api/config', (req, res) => {
  res.json({ googleClientId: GOOGLE_CLIENT_ID });
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password, year, subjects } = req.body || {};
  if (!name || !email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Name, email and a password of at least 6 characters are required.' });
  }
  if (findUserByEmail(email)) {
    return res.status(409).json({ error: 'An account with this email already exists. Try logging in instead.' });
  }
  const users = readUsers();
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: 'u_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    name, email, passwordHash, year: year || '', subjects: subjects || '', provider: 'password',
    createdAt: new Date().toISOString()
  };
  users.push(user);
  writeUsers(users);
  res.json({ token: issueToken(user), user: publicUser(user) });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const user = findUserByEmail(email);
  if (!user || !user.passwordHash) {
    return res.status(401).json({ error: 'No account found with that email and password.' });
  }
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Incorrect email or password.' });
  res.json({ token: issueToken(user), user: publicUser(user) });
});

app.post('/api/google', async (req, res) => {
  const { credential } = req.body || {};
  if (!googleClient) {
    return res.status(500).json({ error: 'Google Sign-In is not configured on the server yet. Set GOOGLE_OAUTH_CLIENT_ID in backend/.env.' });
  }
  if (!credential) return res.status(400).json({ error: 'Missing Google credential.' });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name || email.split('@')[0];
    let user = findUserByEmail(email);
    const users = readUsers();
    if (!user) {
      user = {
        id: 'u_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
        name, email, provider: 'google', googleId: payload.sub, year: '', subjects: '',
        createdAt: new Date().toISOString()
      };
      users.push(user);
      writeUsers(users);
    }
    res.json({ token: issueToken(user), user: publicUser(user) });
  } catch (err) {
    res.status(401).json({ error: 'Could not verify Google sign-in. Please try again.' });
  }
});

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.sub;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

app.get('/api/me', auth, (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: publicUser(user) });
});

app.put('/api/me', auth, (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const { name, year, subjects } = req.body || {};
  if (name) user.name = name;
  if (year !== undefined) user.year = year;
  if (subjects !== undefined) user.subjects = subjects;
  writeUsers(users);
  res.json({ user: publicUser(user) });
});

app.delete('/api/me', auth, (req, res) => {
  let users = readUsers();
  users = users.filter(u => u.id !== req.userId);
  writeUsers(users);
  res.json({ ok: true });
});

// Static frontend
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`StudyFlow.AI server running at http://localhost:${PORT}`);
  if (!GOOGLE_CLIENT_ID) console.log('Note: GOOGLE_OAUTH_CLIENT_ID is not set — Google Sign-In will be disabled until you add it to backend/.env');
});
