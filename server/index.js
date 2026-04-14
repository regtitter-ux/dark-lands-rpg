import express from 'express';
import cors from 'cors';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;

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
    CREATE TABLE IF NOT EXISTS players (
      uuid UUID PRIMARY KEY,
      nick TEXT NOT NULL,
      cls TEXT,
      lvl INT NOT NULL DEFAULT 1,
      stage_max INT NOT NULL DEFAULT 1,
      gold INT NOT NULL DEFAULT 0,
      bosses INT NOT NULL DEFAULT 0,
      save_blob JSONB,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS players_leaderboard
      ON players (lvl DESC, stage_max DESC, gold DESC, bosses DESC);
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS players_nick_lower
      ON players (LOWER(nick));
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

app.post('/api/register', async (req, res) => {
  const nick = String(req.body?.nick || '').trim().slice(0, 24);
  if (!nick || nick.length < 2) return res.status(400).json({ error: 'nick must be 2-24 chars' });
  if (!/^[\p{L}\p{N}_-]+$/u.test(nick)) return res.status(400).json({ error: 'invalid characters in nick' });
  const uuid = crypto.randomUUID();
  try {
    await pool.query(
      `INSERT INTO players (uuid, nick) VALUES ($1, $2)`,
      [uuid, nick]
    );
    res.json({ uuid, nick });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'nick taken' });
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/save', async (req, res) => {
  const uuid = req.headers['x-uuid'];
  if (!uuid || typeof uuid !== 'string') return res.status(401).json({ error: 'no uuid' });
  const { nick, cls, lvl, stage_max, gold, bosses, save_blob } = req.body || {};
  if (typeof lvl !== 'number' || typeof gold !== 'number') {
    return res.status(400).json({ error: 'bad payload' });
  }
  try {
    const r = await pool.query(
      `UPDATE players
       SET nick = COALESCE($2, nick),
           cls = COALESCE($3, cls),
           lvl = $4,
           stage_max = $5,
           gold = $6,
           bosses = $7,
           save_blob = $8,
           updated_at = NOW()
       WHERE uuid = $1
       RETURNING uuid, nick`,
      [uuid, nick || null, cls || null, lvl|0, stage_max|0, gold|0, bosses|0, save_blob || null]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'unknown uuid' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/load', async (req, res) => {
  const uuid = req.query.uuid;
  if (!uuid || typeof uuid !== 'string') return res.status(400).json({ error: 'no uuid' });
  try {
    const r = await pool.query(
      `SELECT uuid, nick, cls, lvl, stage_max, gold, bosses, save_blob, updated_at
       FROM players WHERE uuid = $1`,
      [uuid]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'not found' });
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

app.get('/api/leaderboard', async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT nick, cls, lvl, stage_max, gold, bosses, updated_at
       FROM players
       ORDER BY lvl DESC, stage_max DESC, gold DESC, bosses DESC
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
