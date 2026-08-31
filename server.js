const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD;

if (!DASHBOARD_PASSWORD) {
  console.error('ERROR: DASHBOARD_PASSWORD environment variable is not set.');
  process.exit(1);
}

const SESSION_SECRET = crypto.randomBytes(64).toString('hex');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  // 'lax' so that the SSO bypass cookie set via cross-site link still works
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

// Serve static assets (chart.js etc.) without auth
app.use('/assets', express.static(path.join(__dirname, 'Whitestown Plant Runtime Dashboard _ Hershey_files')));

// ─── Executive SSO bypass ─────────────────────────────────────────────────────
// Shared HMAC secret with the leadership dashboard.
const EXEC_BYPASS_SECRET = process.env.EXEC_BYPASS_SECRET || '';
const EXEC_TOKEN_TTL_MS = 8 * 60 * 60 * 1000;

function verifyExecBypassToken(token) {
  if (!token || !EXEC_BYPASS_SECRET) return null;
  try {
    const [b64, sig] = token.split('.');
    if (!b64 || !sig) return null;
    const data = Buffer.from(b64, 'base64url').toString('utf8');
    const expected = crypto.createHmac('sha256', EXEC_BYPASS_SECRET).update(data).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
    const payload = JSON.parse(data);
    if (!payload.exec) return null;
    if (Date.now() - payload.ts > EXEC_TOKEN_TTL_MS) return null;
    return payload;
  } catch { return null; }
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  // Honor a valid exec bypass token from the leadership dashboard.
  // We do NOT redirect here — browsers may drop a freshly-set cookie on a
  // cross-origin redirect chain. Just authenticate the session and proceed.
  if (req.query.token && verifyExecBypassToken(req.query.token)) {
    req.session.authenticated = true;
    req.session.via = 'exec';
    return next();
  }
  res.redirect('/login');
}

// Login page
app.get('/login', (req, res) => {
  const error = req.query.error ? '<p style="color:red;margin-top:1rem;">Incorrect password. Please try again.</p>' : '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Whitestown Dashboard — Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #512314, #3d1a0f); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: white; border-radius: 12px; padding: 2.5rem 2rem; width: 340px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); text-align: center; }
    h1 { color: #512314; font-size: 1.6rem; margin-bottom: 0.25rem; }
    p.sub { color: #b8860b; font-size: 0.85rem; margin-bottom: 1.75rem; }
    label { display: block; text-align: left; font-size: 0.8rem; color: #555; margin-bottom: 0.35rem; }
    input[type=password] { width: 100%; padding: 0.75rem; border: 2px solid #ddd; border-radius: 8px; font-size: 1rem; outline: none; transition: border 0.2s; }
    input[type=password]:focus { border-color: #512314; }
    button { margin-top: 1.25rem; width: 100%; padding: 0.85rem; background: linear-gradient(135deg, #512314, #3d1a0f); color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }
    button:hover { opacity: 0.9; }
    .error { color: #c62828; font-size: 0.85rem; margin-top: 0.75rem; }
  </style>
</head>
<body>
  <div class="card">
    <svg viewBox="0 0 188.086 50.041" xmlns="http://www.w3.org/2000/svg" xml:space="preserve" style="width: 200px; margin-bottom: 0.25rem;">
      <g transform="matrix(1.0992327,0,0,1.0992327,-9.3974125,-8.2720866)">
        <path fill="#512314" fill-rule="evenodd" d="m 149.422,48.237 c 0,-2.13 1.727,-3.855 3.855,-3.855 2.13,0 3.855,1.726 3.855,3.855 0,2.129 -1.726,3.855 -3.855,3.855 -2.128,0 -3.855,-1.726 -3.855,-3.855 z m 3.856,4.414 c 2.438,0 4.415,-1.977 4.415,-4.414 0,-2.438 -1.977,-4.414 -4.415,-4.414 -2.438,0 -4.414,1.976 -4.414,4.414 0,2.437 1.976,4.414 4.414,4.414 z"/>
        <path fill="#512314" fill-rule="evenodd" d="m 152.246,46.236 h 1.399 c 0.632,0 1.298,0.102 1.298,0.853 0,0.837 -0.7,0.888 -1.366,0.888 h -1.331 z m 3.311,0.887 c 0,-0.973 -0.7,-1.314 -1.759,-1.314 h -2.133 v 4.916 h 0.58 v -2.271 h 1.126 l 1.4,2.271 h 0.717 l -1.502,-2.271 c 0.871,-0.034 1.571,-0.393 1.571,-1.331 z"/>
        <polygon fill="#512314" fill-rule="evenodd" points="158.783,8.599 156.427,18.345 151.871,18.345 154.293,8.599"/>
        <polygon fill="#512314" fill-rule="evenodd" points="139.017,52.09 139.017,34.527 133.317,8.599 140.537,8.599 143.746,27.136 147.261,8.599 151.75,8.599 146.033,34.527 146.033,52.09"/>
        <path fill="#512314" fill-rule="evenodd" d="m 171.925,38.999 v 4.762 c 0,3.056 -1.314,2.834 -2.406,2.834 -1.349,0 -2.458,0 -2.458,-2.783 l -0.051,-6.793 h -6.538 v 8.176 c 0,7.63 4.114,6.862 8.928,6.862 3.874,0 9.421,0.768 9.421,-7.033 v -8.448 c 0,-2.39 -1.246,-4.147 -3.208,-6.11 0,0 -2.186,-1.861 -5.906,-5.582 -2.509,-2.475 -3.056,-4.301 -3.056,-5.991 v -3.567 c 0,-3.038 1.298,-2.799 2.39,-2.799 1.332,0 2.476,0 2.476,2.782 l 0.034,5.462 h 6.554 v -6.008 c 0,-7.629 -4.113,-6.844 -8.943,-6.844 -3.857,0 -9.405,-0.785 -9.405,6.998 v 6.401 c 0,2.373 1.707,4.933 5.77,8.773 -0.002,-0.003 6.398,4.179 6.398,8.908 z"/>
        <path fill="#512314" fill-rule="evenodd" d="m 84.125,38.999 v 4.762 c 0,3.056 -1.297,2.834 -2.39,2.834 -1.331,0 -2.475,0 -2.475,-2.783 l -0.018,-6.793 h -6.554 v 8.176 c 0,7.63 4.097,6.862 8.944,6.862 3.858,0 9.422,0.768 9.422,-7.033 v -8.448 c 0,-2.39 -1.263,-4.147 -3.208,-6.11 0,0 -2.185,-1.861 -5.923,-5.582 -2.526,-2.475 -3.039,-4.301 -3.039,-5.991 v -3.567 c 0,-3.038 1.297,-2.799 2.39,-2.799 1.332,0 2.475,0 2.475,2.782 l 0.034,5.462 h 6.554 v -6.008 c 0,-7.629 -4.113,-6.844 -8.961,-6.844 -3.857,0 -9.405,-0.785 -9.405,6.998 v 6.401 c 0,2.373 1.707,4.933 5.786,8.773 0.002,-0.003 6.368,4.179 6.368,8.908 z"/>
        <path fill="#512314" fill-rule="evenodd" d="m 56.731,13.071 h 1.501 c 2.595,0 2.304,2.987 2.304,6.025 0,0 0.291,5.94 -2.304,5.94 h -1.501 z m -7.289,39.019 h 7.289 V 30.856 h 1.297 c 2.338,0 2.492,1.11 2.492,3.603 v 9.404 c 0,2.901 0.188,6.811 0.973,8.228 h 7.22 c -0.802,-1.417 -0.717,-5.326 -0.717,-8.228 v -7.681 c 0,-4.302 0.153,-7.579 -3.994,-8.33 3.141,-0.478 4.301,-1.877 4.301,-8.722 0,-9.166 -1.553,-10.531 -9.336,-10.531 H 49.443 V 52.09 Z"/>
        <polygon fill="#512314" fill-rule="evenodd" points="130.876,24.951 130.876,30.856 123.366,30.856 123.366,45.826 132.292,45.826 132.292,52.09 116.351,52.09 116.351,8.599 131.934,8.599 131.934,14.368 123.366,14.368 123.366,24.951"/>
        <polygon fill="#512314" fill-rule="evenodd" points="45.192,24.951 45.192,30.856 37.682,30.856 37.682,45.826 46.592,45.826 46.592,52.09 30.65,52.09 30.65,8.599 46.268,8.599 46.268,14.368 37.682,14.368 37.682,24.951"/>
        <polygon fill="#512314" fill-rule="evenodd" points="112.391,8.599 112.391,52.09 105.375,52.09 105.375,30.856 101.331,30.856 101.331,52.09 94.298,52.09 94.298,8.599 101.331,8.599 101.331,24.883 105.375,24.883 105.375,8.599"/>
        <polygon fill="#512314" fill-rule="evenodd" points="27.543,8.599 27.543,52.09 20.528,52.09 20.528,30.856 16.483,30.856 16.483,52.09 9.485,52.09 9.485,8.599 16.483,8.599 16.483,24.883 20.528,24.883 20.528,8.599"/>
      </g>
    </svg>
    <p class="sub">Whitestown Plant Runtime Dashboard</p>
    <form method="POST" action="/login">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter password" autofocus required>
      <button type="submit">Sign In</button>
    </form>
    <div class="error">${error}</div>
  </div>
</body>
</html>`);
});

// Login POST — compare hashed to avoid timing attacks
app.post('/login', (req, res) => {
  const submitted = req.body.password || '';
  const expected = DASHBOARD_PASSWORD;
  const match = crypto.timingSafeEqual(
    Buffer.from(submitted.padEnd(64)),
    Buffer.from(expected.padEnd(64))
  ) && submitted === expected;
  if (match) {
    req.session.authenticated = true;
    res.redirect('/');
  } else {
    res.redirect('/login?error=1');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ===== DMAIC Entries — persistent JSON storage =====
// Use Railway volume (/data) if available, otherwise fall back to local dir
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const DMAIC_FILE = path.join(DATA_DIR, 'dmaic-entries.json');
console.log('DMAIC storage path:', DMAIC_FILE);

function dmaicLoad() {
  try { return JSON.parse(fs.readFileSync(DMAIC_FILE, 'utf8')); }
  catch (e) { return []; }
}
function dmaicSave(entries) {
  fs.writeFileSync(DMAIC_FILE, JSON.stringify(entries, null, 2), 'utf8');
}

// GET all entries
app.get('/api/dmaic', requireAuth, (req, res) => {
  res.json(dmaicLoad());
});

// POST create or update an entry
app.post('/api/dmaic', requireAuth, (req, res) => {
  const entry = req.body;
  if (!entry || !entry.title) return res.status(400).json({ error: 'Title is required' });
  const entries = dmaicLoad();
  if (entry.id) {
    const idx = entries.findIndex(e => e.id === entry.id);
    if (idx !== -1) {
      entry.createdAt = entries[idx].createdAt;
      entry.updatedBy = (req.session.email || 'unknown');
      entry.updatedAt = new Date().toISOString();
      entries[idx] = entry;
    } else {
      entry.createdBy = (req.session.email || 'unknown');
      entry.createdAt = new Date().toISOString();
      entries.push(entry);
    }
  } else {
    entry.id = 'pdca_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    entry.createdBy = (req.session.email || 'unknown');
    entry.createdAt = new Date().toISOString();
    entries.push(entry);
  }
  dmaicSave(entries);
  res.json({ ok: true, entry });
});

// DELETE an entry
app.delete('/api/dmaic/:id', requireAuth, (req, res) => {
  let entries = dmaicLoad();
  const before = entries.length;
  entries = entries.filter(e => e.id !== req.params.id);
  if (entries.length === before) return res.status(404).json({ error: 'Not found' });
  dmaicSave(entries);
  res.json({ ok: true });
});

// ===== Baseline Notes — single shared document =====
const BASELINE_FILE = path.join(DATA_DIR, 'baseline-notes.json');
function baselineLoad() {
  try { return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8')); }
  catch (e) { return { notes: '', updatedBy: '', updatedAt: '' }; }
}
function baselineSave(doc) {
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2), 'utf8');
}
app.get('/api/baseline-notes', requireAuth, (req, res) => {
  res.json(baselineLoad());
});
app.put('/api/baseline-notes', requireAuth, (req, res) => {
  const notes = (req.body && typeof req.body.notes === 'string') ? req.body.notes : '';
  const doc = {
    notes: notes,
    updatedBy: req.session.email || 'unknown',
    updatedAt: new Date().toISOString()
  };
  baselineSave(doc);
  res.json({ ok: true, doc });
});

// ===== Sensor Statuses — per-device metadata (repurposed/retired/etc.) =====
const SENSOR_STATUS_FILE = path.join(DATA_DIR, 'sensor-statuses.json');
function sensorStatusLoad() {
  try { return JSON.parse(fs.readFileSync(SENSOR_STATUS_FILE, 'utf8')); }
  catch (e) { return {}; }
}
function sensorStatusSave(doc) {
  fs.writeFileSync(SENSOR_STATUS_FILE, JSON.stringify(doc, null, 2), 'utf8');
}
app.get('/api/sensor-status', requireAuth, (req, res) => {
  res.json(sensorStatusLoad());
});
app.put('/api/sensor-status', requireAuth, (req, res) => {
  const incoming = (req.body && typeof req.body === 'object') ? req.body : {};
  const existing = sensorStatusLoad();
  // Merge: incoming wins per device. Empty status removes the entry.
  Object.keys(incoming).forEach(function(k) {
    const v = incoming[k];
    if (!v || !v.status) {
      delete existing[k];
    } else {
      existing[k] = {
        status: String(v.status),
        note: String(v.note || ''),
        date: String(v.date || ''),
        updatedBy: req.session.email || 'unknown',
        updatedAt: new Date().toISOString()
      };
    }
  });
  sensorStatusSave(existing);
  res.json({ ok: true, statuses: existing });
});

// ===== Plant Config — single shared document (for $ Impact calc) =====
const PLANT_CONFIG_FILE = path.join(DATA_DIR, 'plant-config.json');
function plantConfigLoad() {
  try { return JSON.parse(fs.readFileSync(PLANT_CONFIG_FILE, 'utf8')); }
  catch (e) { return { throughput: '', price: '', operatingHrsPerYear: 8400, electricityRate: 0.10, updatedBy: '', updatedAt: '' }; }
}
function plantConfigSave(doc) {
  fs.writeFileSync(PLANT_CONFIG_FILE, JSON.stringify(doc, null, 2), 'utf8');
}
app.get('/api/plant-config', requireAuth, (req, res) => res.json(plantConfigLoad()));
app.put('/api/plant-config', requireAuth, (req, res) => {
  const b = req.body || {};
  const doc = {
    throughput: typeof b.throughput === 'number' || (typeof b.throughput === 'string' && b.throughput.trim() !== '') ? Number(b.throughput) : '',
    price: typeof b.price === 'number' || (typeof b.price === 'string' && b.price.trim() !== '') ? Number(b.price) : '',
    operatingHrsPerYear: Number(b.operatingHrsPerYear) || 8400,
    electricityRate: Number(b.electricityRate) || 0.10,
    updatedBy: req.session.email || 'unknown',
    updatedAt: new Date().toISOString()
  };
  plantConfigSave(doc);
  res.json({ ok: true, doc });
});

// Email capture (store in session for PostHog)
app.post('/identify', requireAuth, (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (email) req.session.email = email;
  res.json({ ok: true });
});

// Main dashboard
app.get('/', requireAuth, (req, res) => {
  const htmlPath = path.join(__dirname, 'Whitestown Plant Runtime Dashboard _ Hershey.html');
  res.sendFile(htmlPath);
});

app.listen(PORT, () => {
  console.log(`Whitestown Dashboard running on port ${PORT}`);
});
