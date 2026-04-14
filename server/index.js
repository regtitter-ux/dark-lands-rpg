import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

const { Pool } = pg;

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const TOKEN_TTL = '30d';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower
      ON users (LOWER(username));
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS player_data (
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      cls TEXT,
      lvl INT NOT NULL DEFAULT 1,
      stage_max INT NOT NULL DEFAULT 1,
      gold INT NOT NULL DEFAULT 0,
      bosses INT NOT NULL DEFAULT 0,
      save_blob JSONB,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS player_data_leaderboard
      ON player_data (lvl DESC, stage_max DESC, gold DESC, bosses DESC);
  `);
}

const app = express();
app.use(cors({
  origin: [
    'https://regtitter-ux.github.io',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    /^http:\/\/localhost:\d+$/,
  ],
  credentials: false,
}));
app.use(express.json({ limit: '256kb' }));

app.get('/health', (_req, res) => res.json({ ok: true }));

function validUsername(u) {
  if (typeof u !== 'string') return false;
  const s = u.trim();
  if (s.length < 2 || s.length > 24) return false;
  if (!/^[\p{L}\p{N}_\- .']+$/u.test(s)) return false;
  if (/\s{2,}/.test(s)) return false;
  return true;
}

function validPassword(p) {
  return typeof p === 'string' && p.length >= 6 && p.length <= 128;
}

function signToken(user) {
  return jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'no token' });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'bad token' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  const username = String(req.body?.username || '').trim().slice(0, 24);
  const password = String(req.body?.password || '');
  if (!validUsername(username)) return res.status(400).json({ error: 'invalid username' });
  if (!validPassword(password)) return res.status(400).json({ error: 'password must be 6-128 chars' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username`,
      [username, hash]
    );
    const user = r.rows[0];
    await pool.query(`INSERT INTO player_data (user_id) VALUES ($1)`, [user.id]);
    res.json({ token: signToken(user), username: user.username });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'username taken' });
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) return res.status(400).json({ error: 'bad payload' });
  try {
    const r = await pool.query(
      `SELECT id, username, password_hash FROM users WHERE LOWER(username) = LOWER($1)`,
      [username]
    );
    if (!r.rowCount) return res.status(401).json({ error: 'wrong credentials' });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'wrong credentials' });
    res.json({ token: signToken(u), username: u.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.username, p.cls, p.lvl, p.stage_max, p.gold, p.bosses, p.save_blob, p.updated_at
       FROM users u LEFT JOIN player_data p ON p.user_id = u.id
       WHERE u.id = $1`,
      [req.user.uid]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'not found' });
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/save', auth, async (req, res) => {
  const { cls, lvl, stage_max, gold, bosses, save_blob } = req.body || {};
  if (typeof lvl !== 'number' || typeof gold !== 'number') {
    return res.status(400).json({ error: 'bad payload' });
  }
  try {
    await pool.query(
      `INSERT INTO player_data (user_id, cls, lvl, stage_max, gold, bosses, save_blob, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         cls = COALESCE(EXCLUDED.cls, player_data.cls),
         lvl = EXCLUDED.lvl,
         stage_max = EXCLUDED.stage_max,
         gold = EXCLUDED.gold,
         bosses = EXCLUDED.bosses,
         save_blob = EXCLUDED.save_blob,
         updated_at = NOW()`,
      [req.user.uid, cls || null, lvl|0, stage_max|0, gold|0, bosses|0, save_blob || null]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/leaderboard', async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.username AS nick, p.cls, p.lvl, p.stage_max, p.gold, p.bosses, p.updated_at
       FROM player_data p JOIN users u ON u.id = p.user_id
       ORDER BY p.lvl DESC, p.stage_max DESC, p.gold DESC, p.bosses DESC
       LIMIT 50`
    );
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`server listening on :${PORT}`)))
  .catch(e => { console.error('init failed', e); process.exit(1); });
