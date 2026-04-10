const express = require('express');
const fs      = require('fs');
const path    = require('path');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app        = express();
const PORT       = process.env.PORT || 3000;
const DATA_PATH  = process.env.DATA_PATH || path.join(__dirname, 'data', 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'mycrm-change-this-secret-in-production';

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── helpers ────────────────────────────────────────────────────────────────

function readData() {
  try {
    if (fs.existsSync(DATA_PATH)) return JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
  } catch (e) { console.error('Read error:', e.message); }
  return { users: [], deals: [], contacts: [], companies: [], activities: [] };
}

function writeData(data) {
  try {
    const dir = path.dirname(DATA_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (e) { console.error('Write error:', e.message); return false; }
}

function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2); }

function safeUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, createdAt: u.createdAt };
}

// ─── auth middleware ─────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Kirjaudu sisään' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Istunto vanhentunut, kirjaudu uudelleen' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Vain adminille sallittu' });
    next();
  });
}

// ─── auth routes ─────────────────────────────────────────────────────────────

// Is initial setup needed? (no users yet)
app.get('/api/auth/setup-needed', (req, res) => {
  const data = readData();
  res.json({ needed: !data.users || data.users.length === 0 });
});

// Create first admin (only works if no users exist)
app.post('/api/auth/setup', (req, res) => {
  const data = readData();
  if (data.users?.length > 0) return res.status(400).json({ error: 'Asennus on jo tehty' });

  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Täytä kaikki kentät' });
  if (password.length < 6) return res.status(400).json({ error: 'Salasana vähintään 6 merkkiä' });

  if (!data.users) data.users = [];
  const user = {
    id: uid(), name: name.trim(),
    email: email.toLowerCase().trim(), role: 'admin',
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt: new Date().toISOString()
  };
  data.users.push(user);
  writeData(data);

  const token = jwt.sign(safeUser(user), JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safeUser(user) });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Täytä kaikki kentät' });

  const data = readData();
  const user = data.users?.find(u => u.email === email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Väärä sähköposti tai salasana' });
  }

  const token = jwt.sign(safeUser(user), JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: safeUser(user) });
});

// List users (admin only)
app.get('/api/auth/users', requireAdmin, (req, res) => {
  const data = readData();
  res.json((data.users || []).map(safeUser));
});

// Create user (admin only)
app.post('/api/auth/users', requireAdmin, (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Täytä kaikki kentät' });
  if (password.length < 6) return res.status(400).json({ error: 'Salasana vähintään 6 merkkiä' });

  const data = readData();
  if (!data.users) data.users = [];
  if (data.users.find(u => u.email === email.toLowerCase().trim())) {
    return res.status(400).json({ error: 'Sähköposti on jo käytössä' });
  }

  const user = {
    id: uid(), name: name.trim(),
    email: email.toLowerCase().trim(),
    role: role === 'admin' ? 'admin' : 'user',
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt: new Date().toISOString()
  };
  data.users.push(user);
  writeData(data);
  res.json(safeUser(user));
});

// Delete user (admin only, cannot delete yourself)
app.delete('/api/auth/users/:id', requireAdmin, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Et voi poistaa omaa tiliäsi' });
  const data = readData();
  data.users = (data.users || []).filter(u => u.id !== req.params.id);
  writeData(data);
  res.json({ ok: true });
});

// Change own password
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Täytä kaikki kentät' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Uusi salasana vähintään 6 merkkiä' });

  const data = readData();
  const user = data.users?.find(u => u.id === req.user.id);
  if (!user || !bcrypt.compareSync(currentPassword, user.passwordHash)) {
    return res.status(401).json({ error: 'Nykyinen salasana on väärä' });
  }
  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  writeData(data);
  res.json({ ok: true });
});

// ─── CRM data routes (require auth) ──────────────────────────────────────────

app.get('/api/data', requireAuth, (req, res) => {
  const { users, ...crm } = readData();
  res.json(crm);
});

app.post('/api/data', requireAuth, (req, res) => {
  const { deals, contacts, companies, activities } = req.body;
  if (!Array.isArray(deals)) return res.status(400).json({ error: 'Virheellinen data' });
  const existing = readData();
  const ok = writeData({ ...existing, deals, contacts, companies, activities });
  ok ? res.json({ ok: true }) : res.status(500).json({ error: 'Tallentaminen epäonnistui' });
});

// ─── start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`✅  MyCRM pyörii: http://localhost:${PORT}`);
  console.log(`📁  Data: ${DATA_PATH}`);
});
