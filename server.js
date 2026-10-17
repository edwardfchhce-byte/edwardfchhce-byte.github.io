const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'mars_construct_data');
const DB_FILE = path.join(DATA_DIR, 'accounts.json');
const COOKIE = 'mars_session';
const SESSION_DAYS = 30;
const MAX_SAVE_BYTES = 1_000_000;
let db = { users: {}, sessions: {} };
const online = new Map();
const attempts = new Map();

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

async function persist() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const temp = DB_FILE + '.tmp';
  await fs.writeFile(temp, JSON.stringify(db), { mode: 0o600 });
  await fs.rename(temp, DB_FILE);
}
async function init() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try { db = JSON.parse(await fs.readFile(DB_FILE, 'utf8')); }
  catch (e) { if (e.code !== 'ENOENT') throw e; await persist(); }
  db.users ||= {}; db.sessions ||= {};
  const now = Date.now();
  for (const [token, session] of Object.entries(db.sessions)) if (session.expiresAt < now || !db.users[session.username]) delete db.sessions[token];
  await persist();
}
function safeEqual(a, b) {
  const aa = Buffer.from(a); const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function cookieOptions() {
  const secure = process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
  return `Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure ? '; Secure' : ''}`;
}
function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('='); if (i < 0) continue;
    const k = part.slice(0, i).trim();
    try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch {}
  }
  return out;
}
function sessionKey(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function currentUser(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (!token) return null;
  const s = db.sessions[sessionKey(token)];
  if (!s || s.expiresAt < Date.now()) return null;
  return db.users[s.username] || null;
}
function requireUser(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Please log in again.' });
  req.user = user; next();
}
function newSession(res, username) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.sessions[sessionKey(token)] = { username, expiresAt: Date.now() + SESSION_DAYS * 86400000 };
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; ${cookieOptions()}`);
}
function validateCredentials(body) {
  const username = String(body?.username || '').trim();
  const password = String(body?.password || '');
  if (!/^[A-Za-z0-9_-]{3,20}$/.test(username)) return { error: 'Username must be 3–20 letters, numbers, _ or -.' };
  if (password.length < 8 || password.length > 128) return { error: 'Password must be 8–128 characters.' };
  return { username, password };
}
function limited(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const entry = attempts.get(ip) || { count: 0, until: Date.now() + 60000 };
  if (entry.until < Date.now()) { entry.count = 0; entry.until = Date.now() + 60000; }
  entry.count++;
  attempts.set(ip, entry);
  if (entry.count > 20) return res.status(429).json({ error: 'Too many account attempts. Wait a minute and try again.' });
  next();
}
function derive(password, salt) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (err, key) => err ? reject(err) : resolve(key.toString('hex'))));
}
app.post('/api/register', limited, async (req, res) => {
  try {
    const v = validateCredentials(req.body);
    if (v.error) return res.status(400).json({ error: v.error });
    const key = v.username.toLowerCase();
    if (db.users[key]) return res.status(409).json({ error: 'That username is already taken.' });
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = await derive(v.password, salt);
    db.users[key] = { username: v.username, salt, passwordHash, createdAt: new Date().toISOString(), save: null, publicState: null };
    newSession(res, key); online.set(key, Date.now());
    await persist(); res.json({ ok: true, username: v.username });
  } catch { res.status(500).json({ error: 'Could not create the account.' }); }
});
app.post('/api/login', limited, async (req, res) => {
  try {
    const v = validateCredentials(req.body);
    if (v.error) return res.status(400).json({ error: v.error });
    const key = v.username.toLowerCase(), user = db.users[key];
    if (!user) return res.status(401).json({ error: 'Incorrect username or password.' });
    const hash = await derive(v.password, user.salt);
    if (!safeEqual(hash, user.passwordHash)) return res.status(401).json({ error: 'Incorrect username or password.' });
    newSession(res, key); online.set(key, Date.now()); await persist();
    res.json({ ok: true, username: user.username });
  } catch { res.status(500).json({ error: 'Could not log in.' }); }
});
app.get('/api/me', requireUser, (req, res) => { online.set(req.user.username.toLowerCase(), Date.now()); res.json({ username: req.user.username }); });
app.post('/api/logout', requireUser, async (req, res) => {
  const cookies = parseCookies(req.headers.cookie); if (cookies[COOKIE]) delete db.sessions[sessionKey(cookies[COOKIE])];
  online.delete(req.user.username.toLowerCase()); res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  await persist(); res.json({ ok: true });
});
app.get('/api/load', requireUser, (req, res) => {
  online.set(req.user.username.toLowerCase(), Date.now());
  res.json({ username: req.user.username, save: req.user.save || null });
});
app.post('/api/save', requireUser, async (req, res) => {
  const body = req.body || {};
  const encoded = JSON.stringify(body.save || {});
  if (Buffer.byteLength(encoded) > MAX_SAVE_BYTES) return res.status(413).json({ error: 'Colony save is too large.' });
  if (!body.save || body.save.version !== 1 || !Array.isArray(body.save.buildings) || !Array.isArray(body.save.soldiers)) return res.status(400).json({ error: 'Invalid colony save.' });
  req.user.save = body.save;
  const pub = body.publicState || {};
  req.user.publicState = {
    buildings: Array.isArray(pub.buildings) ? pub.buildings.slice(0, 100).filter(b => b && typeof b.type === 'string' && Number.isFinite(b.x) && Number.isFinite(b.z)).map(b => ({ type: b.type.slice(0, 24), x: b.x, z: b.z, rotation: Number(b.rotation) || 0 })) : [],
    soldiers: Array.isArray(pub.soldiers) ? pub.soldiers.slice(0, 100).filter(s => s && Number.isFinite(s.x) && Number.isFinite(s.z)).map(s => ({ x: s.x, z: s.z, type: String(s.type || 'rifleman').slice(0, 24) })) : [],
    credits: Math.max(0, Math.floor(Number(pub.credits) || 0)), day: Math.max(1, Math.floor(Number(pub.day) || 1)), population: Math.max(0, Math.floor(Number(pub.population) || 0))
  };
  online.set(req.user.username.toLowerCase(), Date.now());
  try { await persist(); res.json({ ok: true, savedAt: new Date().toISOString() }); }
  catch { res.status(500).json({ error: 'Could not save your colony.' }); }
});
app.get('/api/players', requireUser, (req, res) => {
  const now = Date.now(); online.set(req.user.username.toLowerCase(), now);
  const players = [];
  for (const [key, seen] of online) {
    if (now - seen > 35000 || !db.users[key]) { online.delete(key); continue; }
    const u = db.users[key];
    players.push({ username: u.username, publicState: u.publicState || null, day: u.publicState?.day || 1, population: u.publicState?.population || 0 });
  }
  res.json({ players });
});
app.post('/api/ping', requireUser, (req, res) => { online.set(req.user.username.toLowerCase(), Date.now()); res.json({ ok: true }); });

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use(express.static(__dirname, { extensions: ['html'] }));
app.use((err, req, res, next) => { if (err instanceof SyntaxError) return res.status(400).json({ error: 'Invalid request.' }); res.status(500).json({ error: 'Server error.' }); });
init().then(() => app.listen(PORT, '0.0.0.0', () => console.log(`Mars Construct multiplayer server listening on port ${PORT}`))).catch(err => { console.error(err); process.exit(1); });
