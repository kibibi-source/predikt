const express = require('express');
const initSqlJs = require('sql.js');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || readLocalAdminPassword();
const DB_PATH = path.join(__dirname, 'predikt.db');
const ADMIN_TOKEN_TTL_MS = 2 * 60 * 60 * 1000;
const adminTokens = new Map();
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

let db;
let pool;
let dbMode = 'sqlite';

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error('ADMIN_PASSWORD doit contenir au moins 12 caracteres.');
  process.exit(1);
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'"],
      "script-src-attr": ["'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      "font-src": ["'self'", 'https://fonts.gstatic.com'],
      "img-src": ["'self'", 'data:', 'blob:', 'https:', 'http:'],
      "connect-src": ["'self'"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    try {
      const { hostname, port, protocol } = new URL(origin);
      if ((hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') && String(port || '') === String(PORT)) return cb(null, true);
      if (protocol === 'https:' && hostname.endsWith('.onrender.com')) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    } catch (err) {}
    return cb(new Error('Origine non autorisee'));
  }
}));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true }));

app.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 200, message: { error: 'Trop de requêtes' } }));
app.use('/api/respond', rateLimit({ windowMs: 60*60*1000, max: 5, message: { error: 'Tu as déjà répondu' } }));

app.use('/api/admin/login', rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Trop de tentatives' } }));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  dotfiles: 'deny',
  index: false,
  setHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'public, max-age=86400');
  }
}));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => { cb(null, 'q_' + Date.now() + '_' + crypto.randomUUID() + path.extname(file.originalname).toLowerCase()); }
});
const upload = multer({
  storage, limits: { fileSize: 5*1024*1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExt = ['.jpg','.jpeg','.png','.webp','.gif'];
    const allowedMime = ['image/jpeg','image/png','image/webp','image/gif'];
    cb(null, allowedExt.includes(ext) && allowedMime.includes(file.mimetype));
  }
});

// ===================== SQL HELPERS =====================
function pgSql(sql) {
  let i = 0;
  return sql
    .replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'SERIAL PRIMARY KEY')
    .replace(/DATETIME/g, 'TIMESTAMPTZ')
    .replace(/\?/g, () => `$${++i}`);
}

function normalizeRow(row) {
  if (!row) return row;
  ['count', 'c', 'total_responses', 'count_a', 'count_b', 'count_c', 'gain', 'id', 'user_id', 'question_id', 'total'].forEach(k => {
    if (row[k] !== undefined && row[k] !== null && row[k] !== '') row[k] = Number(row[k]);
  });
  return row;
}

async function run(sql, params = []) {
  if (dbMode === 'postgres') {
    await pool.query(pgSql(sql), params);
    return;
  }
  db.run(sql, params);
  saveDb();
}

async function get(sql, params = []) {
  if (dbMode === 'postgres') {
    const result = await pool.query(pgSql(sql), params);
    return normalizeRow(result.rows[0] || null);
  }
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) { const row = stmt.getAsObject(); stmt.free(); return row; }
  stmt.free(); return null;
}

async function all(sql, params = []) {
  if (dbMode === 'postgres') {
    const result = await pool.query(pgSql(sql), params);
    return result.rows.map(normalizeRow);
  }
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free(); return rows;
}

function saveDb() { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); }
function getToday() { return new Date().toISOString().slice(0, 10); }
function getActiveQuestion() { return get('SELECT * FROM questions WHERE is_active = 1 ORDER BY id DESC LIMIT 1'); }

function readLocalAdminPassword() {
  const secretPath = path.join(__dirname, 'M.txt');
  try {
    const values = fs.readFileSync(secretPath, 'utf8').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const passwords = values.filter(v => v.length >= 12 && !v.includes('@'));
    return passwords[passwords.length - 1] || '';
  } catch (err) {
    return '';
  }
}

function timingSafeEqualString(a, b) {
  const ab = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function createAdminToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  adminTokens.set(token, Date.now() + ADMIN_TOKEN_TTL_MS);
  return token;
}

function validateAdminToken(token) {
  token = String(token || '');
  const expiresAt = adminTokens.get(token);
  if (!expiresAt) return false;
  if (expiresAt < Date.now()) {
    adminTokens.delete(token);
    return false;
  }
  return true;
}

function cleanText(value, max = 120) {
  return String(value || '').trim().slice(0, max);
}

function cleanPhone(value) {
  return String(value || '').trim().replace(/[^\d+]/g, '').slice(0, 20);
}

function cleanAnswer(value) {
  const answer = String(value || '').trim().toUpperCase();
  return ['A', 'B', 'C'].includes(answer) ? answer : '';
}

function cleanImageUrl(value) {
  const raw = cleanText(value, 500);
  if (!raw) return '';
  if (raw.startsWith('/uploads/')) return raw;
  try {
    const parsed = new URL(raw);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.toString() : '';
  } catch (err) {
    return '';
  }
}

function csvCell(value) {
  let text = String(value ?? '').replace(/\r?\n/g, ' ').trim();
  if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
  return `"${text.replace(/"/g, '""')}"`;
}

function requireAdmin(req, res, next) {
  const auth = String(req.headers.authorization || '');
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const token = req.headers['x-admin-token'] || bearer || req.body.adminToken;
  if (validateAdminToken(token)) return next();
  return res.status(401).json({ error: 'Non autorise' });
}

// ===================== ROUTES PUBLIQUES =====================
app.post('/api/register', async (req, res) => {
  try {
    const name = cleanText(req.body.name, 60);
    const phone = cleanPhone(req.body.phone);
    const gender = cleanText(req.body.gender, 20);
    const age = cleanText(req.body.age, 20);
    const city = cleanText(req.body.city, 80);
    const commune = cleanText(req.body.commune, 80);
    const interests = Array.isArray(req.body.interests) ? req.body.interests.map(i => cleanText(i, 60)).slice(0, 2) : [];
    if (!name || !phone) return res.status(400).json({ error: 'Prénom et WhatsApp obligatoires' });
    const existing = await get('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing) return res.json({ success: true, userId: existing.id });
    await run('INSERT INTO users (name,phone,gender,age,city,commune,interests) VALUES (?,?,?,?,?,?,?)',
      [name, phone, gender||'', age||'', city||'', commune||'', JSON.stringify(interests||[])]);
    const user = await get('SELECT id FROM users WHERE phone = ?', [phone]);
    res.json({ success: true, userId: user ? user.id : 0 });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/question', async (req, res) => {
  try {
    const q = await getActiveQuestion();
    if (!q) return res.json({ question: null });
    const today = getToday();
    const stats = await all('SELECT answer, COUNT(*) as count FROM responses WHERE question_id=? AND date=? GROUP BY answer', [q.id, today]);
    res.json({
      question: { id:q.id, text:q.text, choiceA:q.choice_a, choiceB:q.choice_b, choiceC:q.choice_c||'', gain:q.gain, imageUrl:q.image_url||'', date:q.date },
      stats: { total: stats.reduce((s,r)=>s+r.count,0), breakdown: stats }
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/respond', async (req, res) => {
  try {
    const phone = cleanPhone(req.body.phone);
    const answer = cleanAnswer(req.body.answer);
    if (!phone || !answer) return res.status(400).json({ error: 'Données manquantes' });
    const user = await get('SELECT * FROM users WHERE phone=?', [phone]);
    if (!user) return res.status(400).json({ error: 'Inscris-toi d\'abord.' });
    const q = await getActiveQuestion();
    if (!q) return res.status(400).json({ error: 'Pas de question active' });
    const today = getToday();
    const already = await get('SELECT id FROM responses WHERE phone=? AND date=?', [phone, today]);
    if (already) return res.status(400).json({ error: 'Tu as déjà joué aujourd\'hui !' });
    await run('INSERT INTO responses (user_id,question_id,phone,name,answer,date) VALUES (?,?,?,?,?,?)',
      [user.id, q.id, phone, user.name, answer, today]);
    const stats = await all('SELECT answer, COUNT(*) as count FROM responses WHERE question_id=? AND date=? GROUP BY answer', [q.id, today]);
    res.json({ success: true, stats: { total: stats.reduce((s,r)=>s+r.count,0), breakdown: stats } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/check/:phone', async (req, res) => {
  try {
    const today = getToday();
    const phone = cleanPhone(req.params.phone);
    res.json({
      registered: !!(await get('SELECT id FROM users WHERE phone=?', [phone])),
      answeredToday: !!(await get('SELECT id FROM responses WHERE phone=? AND date=?', [phone, today]))
    });
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ===================== ROUTES ADMIN =====================
app.post('/api/admin/login', (req, res) => {
  if (timingSafeEqualString(req.body.password, ADMIN_PASSWORD)) res.json({ success: true, token: createAdminToken(), expiresIn: ADMIN_TOKEN_TTL_MS / 1000 });
  else res.status(401).json({ error: 'Mot de passe incorrect' });
});

app.post('/api/admin/question', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const text = cleanText(req.body.text, 500);
    const choiceA = cleanText(req.body.choiceA, 160);
    const choiceB = cleanText(req.body.choiceB, 160);
    const choiceC = cleanText(req.body.choiceC, 160);
    const gain = Number.parseInt(req.body.gain, 10);
    if (!text || !choiceA || !choiceB) return res.status(400).json({ error: 'Question + A + B obligatoires' });
    await run('UPDATE questions SET is_active=0 WHERE is_active=1');
    const imageUrl = req.file ? '/uploads/'+req.file.filename : cleanImageUrl(req.body.imageUrl);
    await run('INSERT INTO questions (text,choice_a,choice_b,choice_c,gain,image_url,is_active,date) VALUES (?,?,?,?,?,?,1,?)',
      [text, choiceA, choiceB, choiceC||'', Number.isFinite(gain) && gain > 0 ? Math.min(gain, 10000000) : 2000, imageUrl, getToday()]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/participants', requireAdmin, async (req, res) => {
  try {
    const q = await getActiveQuestion();
    if (!q) return res.json({ participants: [] });
    res.json({ participants: await all('SELECT r.name,r.phone,r.answer,u.gender,u.age,u.city FROM responses r LEFT JOIN users u ON u.phone=r.phone WHERE r.date=? AND r.question_id=?', [getToday(), q.id]) });
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/admin/winner', requireAdmin, async (req, res) => {
  try {
    const name = cleanText(req.body.name, 60);
    const phone = cleanPhone(req.body.phone);
    if (!name || !phone) return res.status(400).json({ error: 'DonnÃ©es manquantes' });
    const q = await getActiveQuestion();
    const user = await get('SELECT id FROM users WHERE phone=?', [phone]);
    await run('INSERT INTO winners (user_id,question_id,name,phone,gain,question_text,date) VALUES (?,?,?,?,?,?,?)',
      [user?user.id:null, q?q.id:null, name, phone, q?q.gain:2000, q?q.text:'', getToday()]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'Utilisateur invalide' });
    const user = await get('SELECT id, phone FROM users WHERE id=?', [id]);
    if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
    await run('DELETE FROM responses WHERE user_id=? OR phone=?', [id, user.phone]);
    await run('DELETE FROM winners WHERE user_id=? OR phone=?', [id, user.phone]);
    await run('DELETE FROM users WHERE id=?', [id]);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/admin/test-data', requireAdmin, async (req, res) => {
  try {
    const count = Math.max(1, Math.min(Number.parseInt(req.body.count, 10) || 30, 100));
    let q = await getActiveQuestion();
    if (!q) {
      await run('INSERT INTO questions (text,choice_a,choice_b,choice_c,gain,image_url,is_active,date) VALUES (?,?,?,?,?,?,1,?)',
        ['[TEST] Tu choisis quoi aujourd’hui ?', 'Option A', 'Option B', 'Option C', 2000, '', getToday()]);
      q = await getActiveQuestion();
    }

    const names = ['Awa','Kevin','Mariam','Yao','Fatou','Chris','Nadia','Ibrahim','Sarah','Junior','Aya','Moussa'];
    const cities = ['Abidjan','Bouake','Yamoussoukro','San-Pedro','Daloa','Korhogo'];
    const genders = ['Homme','Femme'];
    const ages = ['15-20','21-25','26-30','31-35','36+'];
    const interests = ['Mode & Sneakers','Musique','Sport','Tech','Beaute','Business','Food'];
    const today = getToday();

    for (let i = 0; i < count; i++) {
      const phone = `+2259000${String(i + 1).padStart(4, '0')}`;
      const name = `[TEST] ${names[i % names.length]} ${i + 1}`;
      const gender = genders[i % genders.length];
      const age = ages[i % ages.length];
      const city = cities[i % cities.length];
      const picked = JSON.stringify([interests[i % interests.length], interests[(i + 3) % interests.length]]);
      const existing = await get('SELECT id FROM users WHERE phone=?', [phone]);
      if (!existing) {
        await run('INSERT INTO users (name,phone,gender,age,city,commune,interests) VALUES (?,?,?,?,?,?,?)',
          [name, phone, gender, age, city, city === 'Abidjan' ? 'Cocody' : '', picked]);
      }
      const user = await get('SELECT id FROM users WHERE phone=?', [phone]);
      const answer = ['A','B','C'][i % 3];
      const already = await get('SELECT id FROM responses WHERE phone=? AND date=?', [phone, today]);
      if (!already) {
        await run('INSERT INTO responses (user_id,question_id,phone,name,answer,date) VALUES (?,?,?,?,?,?)',
          [user.id, q.id, phone, name, answer, today]);
      }
    }

    res.json({ success: true, count });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.delete('/api/admin/test-data', requireAdmin, async (req, res) => {
  try {
    const users = await all("SELECT id, phone FROM users WHERE name LIKE '[TEST]%' OR phone LIKE '+2259000%'");
    for (const user of users) {
      await run('DELETE FROM responses WHERE user_id=? OR phone=?', [user.id, user.phone]);
      await run('DELETE FROM winners WHERE user_id=? OR phone=?', [user.id, user.phone]);
      await run('DELETE FROM users WHERE id=?', [user.id]);
    }
    await run("DELETE FROM questions WHERE text LIKE '[TEST]%'");
    res.json({ success: true, count: users.length });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/insights', requireAdmin, async (req, res) => {
  try {
    const today = getToday();
    const q = await getActiveQuestion();
    const totalUsers = (await get('SELECT COUNT(*) as c FROM users')).c;
    const genderStats = await all('SELECT gender, COUNT(*) as count FROM users GROUP BY gender');
    const ageStats = await all('SELECT age, COUNT(*) as count FROM users GROUP BY age ORDER BY age');
    const cityStats = await all('SELECT city, COUNT(*) as count FROM users GROUP BY city ORDER BY count DESC');
    const communeStats = await all("SELECT commune, COUNT(*) as count FROM users WHERE commune!='' GROUP BY commune ORDER BY count DESC");

    const allU = await all('SELECT interests FROM users');
    const interestCounts = {};
    allU.forEach(u => { try { JSON.parse(u.interests||'[]').forEach(i => { interestCounts[i]=(interestCounts[i]||0)+1; }); } catch(e){} });

    let todayStats = null;
    if (q) {
      const tr = await all('SELECT r.answer,u.gender,u.age FROM responses r LEFT JOIN users u ON u.phone=r.phone WHERE r.date=? AND r.question_id=?', [today, q.id]);
      const ab={}, gc={}, ac={};
      tr.forEach(r => {
        ab[r.answer]=(ab[r.answer]||0)+1;
        if(r.gender){ if(!gc[r.gender])gc[r.gender]={}; gc[r.gender][r.answer]=(gc[r.gender][r.answer]||0)+1; }
        if(r.age){ if(!ac[r.age])ac[r.age]={}; ac[r.age][r.answer]=(ac[r.age][r.answer]||0)+1; }
      });
      todayStats = { total:tr.length, answerBreakdown:ab, genderCross:gc, ageCross:ac,
        question:{ text:q.text, choiceA:q.choice_a, choiceB:q.choice_b, choiceC:q.choice_c } };
    }

    const archive = await all(`SELECT q.*,
      (SELECT COUNT(*) FROM responses r WHERE r.question_id=q.id) as total_responses,
      (SELECT COUNT(*) FROM responses r WHERE r.question_id=q.id AND r.answer='A') as count_a,
      (SELECT COUNT(*) FROM responses r WHERE r.question_id=q.id AND r.answer='B') as count_b,
      (SELECT COUNT(*) FROM responses r WHERE r.question_id=q.id AND r.answer='C') as count_c
      FROM questions q WHERE q.is_active=0 ORDER BY q.id DESC`);

    res.json({ totalUsers, genderStats, ageStats, cityStats, communeStats, interestCounts, todayStats, archive,
      winners: await all('SELECT * FROM winners ORDER BY id DESC'),
      users: await all('SELECT * FROM users ORDER BY id DESC') });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/export', requireAdmin, async (req, res) => {
  try {
    const users = await all('SELECT * FROM users ORDER BY id');
    const responses = await all('SELECT r.*,u.gender,u.age,u.city,u.commune FROM responses r LEFT JOIN users u ON u.phone=r.phone ORDER BY r.date DESC');
    const winners = await all('SELECT * FROM winners ORDER BY date DESC');
    let csv = '\uFEFF=== UTILISATEURS ===\nID;Prénom;WhatsApp;Genre;Âge;Ville;Commune;Intérêts\n';
    users.forEach(u => { const i=(() => { try{return JSON.parse(u.interests||'[]').join(', ');}catch(e){return '';} })(); csv+=[u.id,u.name,u.phone,u.gender,u.age,u.city,u.commune,i].map(csvCell).join(';')+'\n'; });
    csv+=`\n\n=== RÉPONSES ===\nPrénom;WhatsApp;Réponse;Genre;Âge;Ville;Date\n`;
    responses.forEach(r => { csv+=[r.name,r.phone,r.answer,r.gender||'',r.age||'',r.city||'',r.date].map(csvCell).join(';')+'\n'; });
    csv+=`\n\n=== GAGNANTS ===\nDate;Prénom;WhatsApp;Gain;Question\n`;
    winners.forEach(w => { csv+=[w.date,w.name,w.phone,w.gain,w.question_text||''].map(csvCell).join(';')+'\n'; });
    res.setHeader('Content-Type','text/csv;charset=utf-8');
    res.setHeader('Content-Disposition',`attachment;filename="PREDIKT_export_${getToday()}.csv"`);
    res.send(csv);
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });

// ===================== START =====================
async function startServer() {
  if (process.env.DATABASE_URL) {
    dbMode = 'postgres';
    const { Pool } = require('pg');
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
    });
    await pool.query('SELECT 1');
  } else {
    dbMode = 'sqlite';
    const SQL = await initSqlJs();
    if (fs.existsSync(DB_PATH)) { db = new SQL.Database(fs.readFileSync(DB_PATH)); }
    else { db = new SQL.Database(); }
  }

  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL, gender TEXT, age TEXT, city TEXT, commune TEXT DEFAULT '', interests TEXT DEFAULT '[]', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS questions (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL, choice_a TEXT NOT NULL, choice_b TEXT NOT NULL, choice_c TEXT DEFAULT '', gain INTEGER DEFAULT 2000, image_url TEXT DEFAULT '', is_active INTEGER DEFAULT 1, date TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS responses (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, question_id INTEGER, phone TEXT NOT NULL, name TEXT, answer TEXT NOT NULL, date TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(phone, date))`);
  await run(`CREATE TABLE IF NOT EXISTS winners (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, question_id INTEGER, name TEXT NOT NULL, phone TEXT NOT NULL, gain INTEGER DEFAULT 2000, question_text TEXT DEFAULT '', date TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);

  app.listen(PORT, () => {
    console.log(`\n🔥 PREDIKT Backend lancé sur http://localhost:${PORT}`);
    console.log('🔐 Auth admin initialisee\n');
  });
}

startServer().catch(err => { console.error('Erreur:', err); process.exit(1); });
