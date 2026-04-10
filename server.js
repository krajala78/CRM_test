const express = require('express');
const fs      = require('fs');
const path    = require('path');

const app       = express();
const PORT      = process.env.PORT || 3000;
const DATA_PATH = process.env.DATA_PATH || path.join(__dirname, 'data', 'db.json');

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- helpers ----------

function readData() {
  try {
    if (fs.existsSync(DATA_PATH)) {
      return JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
    }
  } catch (e) {
    console.error('Read error:', e.message);
  }
  return { deals: [], contacts: [], companies: [], activities: [] };
}

function writeData(data) {
  try {
    const dir = path.dirname(DATA_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('Write error:', e.message);
    return false;
  }
}

// ---------- API routes ----------

// GET all data
app.get('/api/data', (req, res) => {
  res.json(readData());
});

// POST = full replace (simple & reliable for small teams)
app.post('/api/data', (req, res) => {
  const { deals, contacts, companies, activities } = req.body;
  if (!Array.isArray(deals)) return res.status(400).json({ error: 'Invalid payload' });
  const ok = writeData({ deals, contacts, companies, activities });
  ok ? res.json({ ok: true }) : res.status(500).json({ error: 'Tallentaminen epäonnistui' });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date() }));

// ---------- start ----------

app.listen(PORT, () => {
  console.log(`✅ MyCRM pyörii: http://localhost:${PORT}`);
  console.log(`📁 Data-tiedosto: ${DATA_PATH}`);
});
