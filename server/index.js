import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

const { Pool } = pg;

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
let JWT_SECRET = process.env.JWT_SECRET || null;
const TOKEN_TTL = '30d';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  statement_timeout: 5000,
});
pool.on('error', err => console.error('[pg pool] idle client error:', err.message));

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
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS pvp_kills INT NOT NULL DEFAULT 0;
  `);
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS pending_gold_delta INT NOT NULL DEFAULT 0;
  `);
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS resources JSONB NOT NULL DEFAULT '{}'::jsonb;
  `);
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS resources_migrated BOOLEAN NOT NULL DEFAULT FALSE;
  `);
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS pvp_stats JSONB NOT NULL DEFAULT '{}'::jsonb;
  `);
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS pvp_spell_lvl JSONB NOT NULL DEFAULT '{}'::jsonb;
  `);
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 0;
  `);
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS gold_save_at BIGINT NOT NULL DEFAULT 0;
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS market_state (
      key TEXT PRIMARY KEY,
      stock JSONB NOT NULL DEFAULT '{}',
      prices JSONB NOT NULL DEFAULT '{}',
      news JSONB NOT NULL DEFAULT '[]',
      next_at BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  if (!JWT_SECRET) {
    const r = await pool.query(`SELECT value FROM app_meta WHERE key = 'jwt_secret'`);
    if (r.rowCount) {
      JWT_SECRET = r.rows[0].value;
    } else {
      JWT_SECRET = crypto.randomBytes(48).toString('hex');
      await pool.query(
        `INSERT INTO app_meta (key, value) VALUES ('jwt_secret', $1)
         ON CONFLICT (key) DO NOTHING`,
        [JWT_SECRET]
      );
      const r2 = await pool.query(`SELECT value FROM app_meta WHERE key = 'jwt_secret'`);
      JWT_SECRET = r2.rows[0].value;
    }
  }
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

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(503).json({ ok: false, error: 'db unreachable' });
  }
});

// Simple per-IP sliding-window rate limiter for auth endpoints.
const AUTH_WINDOW_MS = 60000;
const AUTH_MAX_PER_WINDOW = 10;
const authHits = new Map(); // ip -> number[] (timestamps)
function authRateLimit(req, res, next) {
  const ip = (req.headers['x-forwarded-for'] || req.ip || req.socket?.remoteAddress || '')
    .toString().split(',')[0].trim();
  const now = Date.now();
  const cutoff = now - AUTH_WINDOW_MS;
  const arr = (authHits.get(ip) || []).filter(t => t > cutoff);
  if (arr.length >= AUTH_MAX_PER_WINDOW) {
    return res.status(429).json({ error: 'too many attempts, try later' });
  }
  arr.push(now);
  authHits.set(ip, arr);
  next();
}
setInterval(() => {
  const cutoff = Date.now() - AUTH_WINDOW_MS;
  for (const [ip, arr] of authHits) {
    const kept = arr.filter(t => t > cutoff);
    if (kept.length) authHits.set(ip, kept); else authHits.delete(ip);
  }
}, AUTH_WINDOW_MS).unref();

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
  return jwt.sign(
    { uid: user.id, username: user.username, tv: user.token_version|0 },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL }
  );
}

// Cache token_version lookups (userId -> { tv, at }) to avoid a DB round-trip on every auth.
const tvCache = new Map();
const TV_CACHE_MS = 30000;
function invalidateTv(uid) { tvCache.delete(uid); }
async function getTokenVersion(uid) {
  const now = Date.now();
  const c = tvCache.get(uid);
  if (c && now - c.at < TV_CACHE_MS) return c.tv;
  const r = await pool.query(`SELECT token_version FROM users WHERE id = $1`, [uid]);
  const tv = r.rowCount ? (r.rows[0].token_version|0) : -1;
  tvCache.set(uid, { tv, at: now });
  return tv;
}
setInterval(() => {
  const cutoff = Date.now() - TV_CACHE_MS * 2;
  for (const [k, v] of tvCache) if (v.at < cutoff) tvCache.delete(k);
}, TV_CACHE_MS).unref();

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'no token' });
  let payload;
  try { payload = jwt.verify(m[1], JWT_SECRET); }
  catch { return res.status(401).json({ error: 'bad token' }); }
  try {
    const currentTv = await getTokenVersion(payload.uid);
    if (currentTv < 0) return res.status(401).json({ error: 'account gone' });
    if ((payload.tv|0) !== currentTv) return res.status(401).json({ error: 'token revoked' });
  } catch {
    return res.status(503).json({ error: 'auth db unavailable' });
  }
  req.user = payload;
  next();
}

app.post('/api/auth/register', authRateLimit, async (req, res) => {
  const username = String(req.body?.username || '').trim().slice(0, 24);
  const password = String(req.body?.password || '');
  if (!validUsername(username)) return res.status(400).json({ error: 'invalid username' });
  if (!validPassword(password)) return res.status(400).json({ error: 'password must be 6-128 chars' });
  const client = await pool.connect();
  try {
    const hash = await bcrypt.hash(password, 10);
    await client.query('BEGIN');
    const r = await client.query(
      `INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, token_version`,
      [username, hash]
    );
    const user = r.rows[0];
    await client.query(`INSERT INTO player_data (user_id) VALUES ($1)`, [user.id]);
    await client.query('COMMIT');
    res.json({ token: signToken(user), username: user.username });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    if (e.code === '23505') return res.status(409).json({ error: 'username taken' });
    console.error(e);
    res.status(500).json({ error: 'db error' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) return res.status(400).json({ error: 'bad payload' });
  try {
    const r = await pool.query(
      `SELECT id, username, password_hash, token_version FROM users WHERE LOWER(username) = LOWER($1)`,
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
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Lock row, flush pending delta, and read — all atomically. (M4)
    await client.query(
      `SELECT 1 FROM player_data WHERE user_id = $1 FOR UPDATE`,
      [req.user.uid]
    );
    await client.query(
      `UPDATE player_data
         SET gold = GREATEST(0, gold + pending_gold_delta), pending_gold_delta = 0
       WHERE user_id = $1 AND pending_gold_delta <> 0`,
      [req.user.uid]
    );
    const r = await client.query(
      `SELECT u.username, p.cls, p.lvl, p.stage_max, p.gold, p.bosses, p.pvp_kills,
              p.save_blob, p.resources, p.updated_at
         FROM users u LEFT JOIN player_data p ON p.user_id = u.id
        WHERE u.id = $1`,
      [req.user.uid]
    );
    await client.query('COMMIT');
    if (!r.rowCount) return res.status(404).json({ error: 'not found' });
    const row = r.rows[0];
    row.resources = sanitizeResources(row.resources);
    res.json(row);
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error(e);
    res.status(500).json({ error: 'db error' });
  } finally {
    client.release();
  }
});

app.delete('/api/me', auth, async (req, res) => {
  const password = String(req.body?.password || '');
  if (!password) return res.status(400).json({ error: 'password required' });
  try {
    const r = await pool.query(
      `SELECT password_hash FROM users WHERE id = $1`,
      [req.user.uid]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'not found' });
    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'wrong password' });
    // Bump token_version before delete so any in-flight tokens are rejected.
    await pool.query(`UPDATE users SET token_version = token_version + 1 WHERE id = $1`, [req.user.uid]);
    invalidateTv(req.user.uid);
    await pool.query(`DELETE FROM users WHERE id = $1`, [req.user.uid]);
    arena.delete(req.user.uid);
    lastDeathAt.delete(req.user.uid);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

// ==================== ANTI-CHEAT CAPS ====================
// Absolute per-level ceilings; client-reported values above these are clamped.
const MAX_LVL           = 500;
const MAX_STAGE         = 999;
const MAX_BOSSES        = 99999;
const MAX_PVP_KILLS     = 999999;
// Gold rate cap (per real second), scales with level. Chosen to comfortably cover
// legitimate farming at that level without permitting orders-of-magnitude inflation.
const GOLD_GAIN_BASE_PER_SEC = 30;
const GOLD_GAIN_PER_LVL_PER_SEC = 6;
// Level-up rate — nobody legitimately gains >N levels without real time.
const LVL_GAIN_BASE_PER_MIN = 3;   // at very low levels you can pop a few levels/min
const LVL_GAIN_FLOOR_PER_SAVE = 5; // always allow at least this many per save
// Stage progression
const STAGE_GAIN_PER_MIN = 15;
const STAGE_FLOOR_PER_SAVE = 10;
// Boss kills
const BOSS_GAIN_PER_MIN = 5;
const BOSS_FLOOR_PER_SAVE = 5;
// Minimum interval "credit" — first save after a long gap still gets a bounded bucket.
const GAIN_BUCKET_MAX_S = 3600;    // cap at 1h of accumulated allowance
const GAIN_BUCKET_MIN_S = 5;       // first save gets at least this much allowance

// Inventory anti-dupe: per-item and total gain caps per save.
const INV_ITEM_GAIN_PER_MIN   = 30;  // any one item can grow by this many / min
const INV_ITEM_FLOOR_PER_SAVE = 10;  // minimum allowance for short-interval saves
const INV_ITEM_ABS_MAX        = 9999;
const INV_TOTAL_GAIN_PER_MIN  = 80;  // sum across all items
const INV_TOTAL_FLOOR_PER_SAVE = 30;

// Quest anti-cheat.
const QUEST_COMPLETE_PER_SAVE = 3;   // can't legit finish more than this between saves
const QUEST_ID_MAX_LEN = 32;
const QUEST_ID_RE = /^[a-z0-9_]{1,32}$/i;

function allowanceSeconds(prevAtMs, nowMs) {
  if (!prevAtMs) return GAIN_BUCKET_MIN_S;
  const dt = Math.max(0, Math.floor((nowMs - prevAtMs) / 1000));
  return Math.max(GAIN_BUCKET_MIN_S, Math.min(GAIN_BUCKET_MAX_S, dt));
}

// Resources (r_*) in save_blob.P.inv are authoritative from the DB resources column and must
// be passed through without clamping.
const RESOURCE_KEY_RE = /^r_/;

// Clean one save_blob.inv map against the previous inv, clamping individual and total growth.
function validateInv(prevInv, nextInv, allowMin) {
  const out = {};
  const prev = (prevInv && typeof prevInv === 'object') ? prevInv : {};
  const next = (nextInv && typeof nextInv === 'object') ? nextInv : {};
  const perItemCap = Math.max(INV_ITEM_FLOOR_PER_SAVE, Math.ceil(INV_ITEM_GAIN_PER_MIN * allowMin));
  const totalCap   = Math.max(INV_TOTAL_FLOOR_PER_SAVE, Math.ceil(INV_TOTAL_GAIN_PER_MIN * allowMin));
  let clamped = false;
  let totalPrev = 0, totalNext = 0;
  for (const [k, v] of Object.entries(prev)) {
    if (RESOURCE_KEY_RE.test(k)) continue; // exclude resources from totals
    totalPrev += Math.max(0, Number(v)|0);
  }
  const keys = new Set([...Object.keys(prev), ...Object.keys(next)]);
  for (const k of keys) {
    if (!QUEST_ID_RE.test(k)) { clamped = true; continue; } // reject weird keys
    if (RESOURCE_KEY_RE.test(k)) {
      // Resources pass-through (authoritative DB side overwrites anyway on load).
      const n = Math.max(0, Math.min(999999, Number(next[k])|0));
      if (n > 0) out[k] = n;
      continue;
    }
    const p = Math.max(0, Math.min(INV_ITEM_ABS_MAX, Number(prev[k])|0));
    const n = Math.max(0, Math.min(INV_ITEM_ABS_MAX, Number(next[k])|0));
    let v;
    if (n <= p) v = n;                                   // decrease/stay: trust
    else v = Math.min(n, p + perItemCap);                // cap growth
    if (v !== n) clamped = true;
    if (v > 0) out[k] = v;
    totalNext += v;
  }
  // Second pass: total cap.
  if (totalNext > totalPrev + totalCap) {
    clamped = true;
    const roomLeft = Math.max(0, (totalPrev + totalCap));
    // Proportionally shrink grown entries so their sum equals roomLeft, preserving per-item floors at prev.
    const grown = [];
    let grownSum = 0;
    let preservedSum = 0;
    for (const [k, v] of Object.entries(out)) {
      const p = Math.max(0, Math.min(INV_ITEM_ABS_MAX, Number(prev[k])|0));
      if (v > p) { grown.push([k, p, v - p]); grownSum += v - p; }
      else preservedSum += v;
    }
    const allowedGrowth = Math.max(0, roomLeft - preservedSum);
    if (grownSum > 0 && allowedGrowth < grownSum) {
      const ratio = allowedGrowth / grownSum;
      for (const [k, p, delta] of grown) {
        const grantedDelta = Math.floor(delta * ratio);
        const v = p + grantedDelta;
        if (v > 0) out[k] = v; else delete out[k];
      }
    }
  }
  return { inv: out, clamped };
}

function validateQuests(prevQ, nextQ, allowS) {
  // Shape: { active: {qid:{kills,visited}}, completed: [qid], available: [qid] }
  const out = { active: {}, completed: [], available: [] };
  const prev = (prevQ && typeof prevQ === 'object') ? prevQ : {};
  const next = (nextQ && typeof nextQ === 'object') ? nextQ : {};
  let clamped = false;

  const prevCompleted = Array.isArray(prev.completed) ? prev.completed.filter(x => QUEST_ID_RE.test(String(x||''))) : [];
  const nextCompleted = Array.isArray(next.completed) ? next.completed.filter(x => QUEST_ID_RE.test(String(x||''))) : [];
  // Completed is monotonic: previously completed can't disappear.
  const prevSet = new Set(prevCompleted);
  for (const q of prevCompleted) if (!nextCompleted.includes(q)) clamped = true;
  // Additions capped.
  const additions = nextCompleted.filter(q => !prevSet.has(q));
  const saveAllowance = Math.max(QUEST_COMPLETE_PER_SAVE, Math.ceil((allowS / 60) * QUEST_COMPLETE_PER_SAVE));
  if (additions.length > saveAllowance) { additions.length = saveAllowance; clamped = true; }
  out.completed = [...prevCompleted, ...additions];

  // Active/available: sanitize IDs & shapes (no strict cap — these don't grant rewards directly).
  if (next.active && typeof next.active === 'object') {
    for (const [qid, v] of Object.entries(next.active)) {
      if (!QUEST_ID_RE.test(qid)) { clamped = true; continue; }
      if (out.completed.includes(qid)) continue; // can't be active & completed
      out.active[qid] = {
        kills: Math.max(0, Math.min(9999, Number(v?.kills)|0)),
        visited: !!v?.visited,
      };
    }
  }
  if (Array.isArray(next.available)) {
    const seen = new Set();
    for (const qid of next.available) {
      const s = String(qid || '');
      if (!QUEST_ID_RE.test(s) || out.completed.includes(s) || seen.has(s)) continue;
      seen.add(s);
      out.available.push(s);
    }
  }
  return { quests: out, clamped };
}

app.post('/api/save', auth, async (req, res) => {
  const { cls, lvl, stage_max, gold, bosses, save_blob, pvp_stats, pvp_spell_lvl } = req.body || {};
  if (typeof lvl !== 'number' || typeof gold !== 'number') {
    return res.status(400).json({ error: 'bad payload' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = await client.query(
      `SELECT lvl, stage_max, gold, bosses, pending_gold_delta, resources_migrated,
              gold_save_at, pvp_kills, save_blob, updated_at
         FROM player_data WHERE user_id = $1 FOR UPDATE`,
      [req.user.uid]
    );
    const prev = cur.rows[0] || null;
    const prevBlob = prev?.save_blob || null;
    const prevInv = prevBlob?.P?.inv || {};
    const prevQuests = prevBlob?.P?.quests || null;
    const now = Date.now();
    const prevAt = prev?.gold_save_at ? Number(prev.gold_save_at) : 0;
    const allowS = allowanceSeconds(prevAt, now);
    const allowMin = allowS / 60;

    // Server-authoritative state: stored gold + pending PvP delta (events the client
    // doesn't yet know about — e.g. they died on arena while offline).
    const prevStoredGold = prev?.gold|0;
    const prevPending    = prev?.pending_gold_delta|0;
    const serverGoldEff  = Math.max(0, prevStoredGold + prevPending);

    // --- lvl: monotonic, capped gain rate.
    const clientLvl = Math.max(1, Math.min(MAX_LVL, Math.floor(lvl)));
    const prevLvl = prev?.lvl|0 || 1;
    const lvlCap = prevLvl + Math.max(LVL_GAIN_FLOOR_PER_SAVE, Math.ceil(LVL_GAIN_BASE_PER_MIN * allowMin));
    const safeLvl = Math.min(Math.max(prevLvl, clientLvl), lvlCap);

    // --- stage_max: monotonic, capped gain.
    const clientStage = Math.max(1, Math.min(MAX_STAGE, Math.floor(stage_max|0) || 1));
    const prevStage = prev?.stage_max|0 || 1;
    const stageCap = prevStage + Math.max(STAGE_FLOOR_PER_SAVE, Math.ceil(STAGE_GAIN_PER_MIN * allowMin));
    const safeStage = Math.min(Math.max(prevStage, clientStage), stageCap);

    // --- bosses: monotonic, capped gain.
    const clientBosses = Math.max(0, Math.min(MAX_BOSSES, Math.floor(bosses|0)));
    const prevBosses = prev?.bosses|0;
    const bossCap = prevBosses + Math.max(BOSS_FLOOR_PER_SAVE, Math.ceil(BOSS_GAIN_PER_MIN * allowMin));
    const safeBosses = Math.min(Math.max(prevBosses, clientBosses), bossCap);

    // --- gold: client reports an absolute value. Interpret as:
    //   client_delta = clientGold - prev_stored   (positive: earned; negative: spent)
    //   safeGold = prev_stored + clamp(client_delta) + pending
    // This preserves PvP pending losses/gains even if the client was unaware of them.
    const clientGold = Math.max(0, Math.min(2_000_000_000, Math.floor(gold)));
    const goldRate = GOLD_GAIN_BASE_PER_SEC + GOLD_GAIN_PER_LVL_PER_SEC * safeLvl;
    const goldGainCap = Math.ceil(goldRate * allowS);
    const clientDelta = clientGold - prevStoredGold;
    let allowedDelta;
    if (clientDelta <= 0) allowedDelta = clientDelta;      // decreases: trust
    else allowedDelta = Math.min(clientDelta, goldGainCap); // increases: cap
    const safeGold = Math.max(0, prevStoredGold + allowedDelta + prevPending);
    const goldCapClamped = (clientDelta > 0) && (allowedDelta < clientDelta);
    // pvpLoss: how much server-enforced PvP debit the client didn't know about yet.
    // Positive = player lost gold; negative = player gained (unlikely, but safe to report).
    const pvpLoss = (prevPending < 0) ? -prevPending : 0;
    const pvpGain = (prevPending > 0) ?  prevPending : 0;

    const needMigrate = !prev || prev.resources_migrated === false;
    const seedResources = needMigrate ? sanitizeResources(save_blob?.P?.inv || {}) : null;

    const cleanStats = pvp_stats ? sanitizeStats(pvp_stats, safeLvl) : null;
    const cleanSpellLvl = sanitizeSpellLvl(pvp_spell_lvl);

    // --- inv & quests validation inside save_blob (anti-dupe, anti-skip).
    let invClamped = false, questsClamped = false;
    let safeBlob = save_blob;
    if (save_blob && typeof save_blob === 'object' && save_blob.P && typeof save_blob.P === 'object') {
      const invRes    = validateInv(prevInv, save_blob.P.inv || {}, allowMin);
      const questsRes = validateQuests(prevQuests, save_blob.P.quests, allowS);
      invClamped = invRes.clamped;
      questsClamped = questsRes.clamped;
      // Shallow-copy to avoid mutating caller's object.
      safeBlob = { ...save_blob, P: { ...save_blob.P, inv: invRes.inv, quests: questsRes.quests } };
    }

    const r = await client.query(
      `INSERT INTO player_data (user_id, cls, lvl, stage_max, gold, bosses, save_blob, resources, resources_migrated,
                                pvp_stats, pvp_spell_lvl, gold_save_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8::jsonb, '{}'::jsonb), $9,
               COALESCE($10::jsonb, '{}'::jsonb), COALESCE($11::jsonb, '{}'::jsonb), $12, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         cls = COALESCE(EXCLUDED.cls, player_data.cls),
         lvl = EXCLUDED.lvl,
         stage_max = EXCLUDED.stage_max,
         gold = EXCLUDED.gold,
         bosses = EXCLUDED.bosses,
         save_blob = EXCLUDED.save_blob,
         resources = CASE WHEN player_data.resources_migrated THEN player_data.resources
                          ELSE COALESCE($8::jsonb, '{}'::jsonb) END,
         resources_migrated = TRUE,
         pvp_stats = COALESCE($10::jsonb, player_data.pvp_stats),
         pvp_spell_lvl = COALESCE($11::jsonb, player_data.pvp_spell_lvl),
         pending_gold_delta = 0,
         gold_save_at = $12,
         updated_at = NOW()
       RETURNING gold, pvp_kills, resources`,
      [req.user.uid, cls || null, safeLvl, safeStage, safeGold, safeBosses, safeBlob || null,
       seedResources ? JSON.stringify(seedResources) : null, true,
       cleanStats ? JSON.stringify(cleanStats) : null,
       cleanSpellLvl ? JSON.stringify(cleanSpellLvl) : null,
       now]
    );
    await client.query('COMMIT');
    const row = r.rows[0] || {};
    const clamped = (clientLvl !== safeLvl) || (clientStage !== safeStage) ||
                    (clientBosses !== safeBosses) || goldCapClamped ||
                    invClamped || questsClamped;
    res.json({
      ok: true,
      gold: row.gold|0,
      lvl: safeLvl,
      stage_max: safeStage,
      bosses: safeBosses,
      pvp_kills: row.pvp_kills|0,
      resources: sanitizeResources(row.resources),
      inv: (invClamped && safeBlob?.P?.inv) ? safeBlob.P.inv : undefined,
      quests: (questsClamped && safeBlob?.P?.quests) ? safeBlob.P.quests : undefined,
      pvp_loss: pvpLoss || undefined,
      pvp_gain: pvpGain || undefined,
      gold_clamped: goldCapClamped || undefined,
      clamped: clamped || undefined,
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error(e);
    res.status(500).json({ error: 'db error' });
  } finally {
    client.release();
  }
});

// ==================== SHARED MARKET ====================
const RESOURCE_IDS = ['r_fur','r_herb','r_ore','r_silk','r_gem','r_spice'];
const RESOURCE_BASE = { r_fur:8, r_herb:6, r_ore:12, r_silk:18, r_gem:45, r_spice:30 };
const RESOURCE_NAMES = { r_fur:'мех', r_herb:'травы', r_ore:'руда', r_silk:'шёлк', r_gem:'самоцветы', r_spice:'пряности' };
const LOCATION_IDS = ['village','forest','swamp','cave','crypt','ruins','port','mountains','volcano','lair'];
const TRADER_NAMES = {
  village:'Торговец Гуго', forest:'Лесник Ториг', swamp:'Ведьма Мирра',
  cave:'Гном-старатель Бром', crypt:'Старьёвщик Сельд', ruins:'Коллекционер Элгар',
  port:'Капитан Рен', mountains:'Шерп Ивор', volcano:'Огневар Ксант', lair:'Торговец-призрак'
};
const EVENT_TEMPLATES = [
  { kind:'up', mul:[1.6,2.2], tpl:(t,r)=>`У ${t} пожар на складе — ${r} почти не осталось, цена взлетела.` },
  { kind:'up', mul:[1.5,2.0], tpl:(t,r)=>`${t} срочно скупает ${r}: готовится большой заказ.` },
  { kind:'up', mul:[1.7,2.4], tpl:(t,r)=>`Слух: в округе ${t} эпидемия — ${r} в цене.` },
  { kind:'up', mul:[1.5,1.9], tpl:(t,r)=>`Караван с ${r} не дошёл до ${t} — торговец поднял цену.` },
  { kind:'up', mul:[1.4,1.8], tpl:(t,r)=>`${t} объявил награду за ${r}: запасы иссякли.` },
  { kind:'down', mul:[0.35,0.6], tpl:(t,r)=>`К ${t} прибыл караван — ${r} в избытке, цены обвалились.` },
  { kind:'down', mul:[0.4,0.65], tpl:(t,r)=>`Охотники завалили склад ${t} — ${r} некуда девать.` },
  { kind:'down', mul:[0.45,0.7], tpl:(t,r)=>`У ${t} портится ${r} — сбывает задёшево.` },
  { kind:'down', mul:[0.4,0.6], tpl:(t,r)=>`${t} получил долг ${r}ом — ему бы скинуть лишнее.` }
];
const MARKET_PERIOD_MS = 60000;
const MAX_TRADE_QTY = 9999;
const MAX_CREDIT_PER_CALL = 5;      // was 20 — drops are per-kill, should be small
const CREDIT_RATE_WINDOW_MS = 60000;
const CREDIT_RATE_MAX = 60;         // was 120 — 1/sec average is plenty
const CREDIT_TOTAL_PER_MIN_BASE = 30;   // total resource units / min at lvl 1
const CREDIT_TOTAL_PER_MIN_PER_LVL = 4; // + per level
const creditRate = new Map();
const market = { prices:{}, stock:{}, news:[], nextAt:0, loaded:false };
for (const loc of LOCATION_IDS) market.stock[loc] = Object.fromEntries(RESOURCE_IDS.map(r=>[r,0]));

// per-key async mutex for market trades (prevents stock race across concurrent buys).
// Bounded by LOCATION_IDS × RESOURCE_IDS (= 60 keys), so no eviction needed.
const tradeLocks = new Map();
function withTradeLock(key, fn) {
  const prev = tradeLocks.get(key) || Promise.resolve();
  const run = prev.then(fn, fn);
  tradeLocks.set(key, run.catch(() => {}));
  return run;
}

function snapshotMarket() {
  return { prices: market.prices, stock: market.stock, news: market.news, nextAt: market.nextAt };
}

// Debounced market persistence: coalesces trade bursts into one DB write per window. (M2)
const MARKET_PERSIST_DEBOUNCE_MS = 1500;
const MARKET_PERSIST_MAX_DELAY_MS = 5000;
let marketPersistTimer = null;
let marketPersistFirstDirtyAt = 0;
async function doPersistMarket() {
  try {
    await pool.query(
      `INSERT INTO market_state (key, stock, prices, news, next_at, updated_at)
         VALUES ('singleton', $1::jsonb, $2::jsonb, $3::jsonb, $4, NOW())
       ON CONFLICT (key) DO UPDATE
         SET stock = EXCLUDED.stock, prices = EXCLUDED.prices,
             news = EXCLUDED.news, next_at = EXCLUDED.next_at,
             updated_at = NOW()`,
      [JSON.stringify(market.stock), JSON.stringify(market.prices),
       JSON.stringify(market.news), market.nextAt]
    );
  } catch (e) { console.error('market persist failed:', e.message); }
}
function persistMarket() {
  const now = Date.now();
  if (!marketPersistFirstDirtyAt) marketPersistFirstDirtyAt = now;
  if (marketPersistTimer) clearTimeout(marketPersistTimer);
  const delay = Math.min(
    MARKET_PERSIST_DEBOUNCE_MS,
    Math.max(0, MARKET_PERSIST_MAX_DELAY_MS - (now - marketPersistFirstDirtyAt))
  );
  marketPersistTimer = setTimeout(() => {
    marketPersistTimer = null;
    marketPersistFirstDirtyAt = 0;
    doPersistMarket();
  }, delay);
  marketPersistTimer.unref?.();
}
// Flush on graceful shutdown so we don't lose pending stock/price updates.
async function flushMarket() {
  if (marketPersistTimer) { clearTimeout(marketPersistTimer); marketPersistTimer = null; }
  marketPersistFirstDirtyAt = 0;
  await doPersistMarket();
}
async function loadMarket() {
  try {
    const r = await pool.query(
      `SELECT stock, prices, news, next_at FROM market_state WHERE key = 'singleton'`
    );
    if (r.rowCount) {
      market.stock  = r.rows[0].stock  || {};
      market.prices = r.rows[0].prices || {};
      market.news   = r.rows[0].news   || [];
      market.nextAt = Number(r.rows[0].next_at) || 0;
    }
    for (const loc of LOCATION_IDS) {
      if (!market.stock[loc]) market.stock[loc] = {};
      for (const rid of RESOURCE_IDS) {
        if (typeof market.stock[loc][rid] !== 'number') market.stock[loc][rid] = 0;
      }
    }
    market.loaded = true;
  } catch (e) { console.error('market load failed:', e.message); market.loaded = true; }
}

function rndF(a,b){ return a + Math.random()*(b-a); }
function regenMarket() {
  const prices = {}, news = [];
  for (const loc of LOCATION_IDS) {
    prices[loc] = {};
    for (const rid of RESOURCE_IDS) {
      prices[loc][rid] = Math.max(1, Math.round(RESOURCE_BASE[rid] * rndF(0.85, 1.15)));
    }
  }
  const used = new Set();
  const eventCount = 2 + Math.floor(Math.random()*2);
  for (let i=0;i<eventCount;i++) {
    const tpl = EVENT_TEMPLATES[Math.floor(Math.random()*EVENT_TEMPLATES.length)];
    let loc, rid, key;
    for (let t=0;t<12;t++) {
      loc = LOCATION_IDS[Math.floor(Math.random()*LOCATION_IDS.length)];
      rid = RESOURCE_IDS[Math.floor(Math.random()*RESOURCE_IDS.length)];
      key = loc+':'+rid;
      if (!used.has(key)) break;
    }
    if (used.has(key)) continue;
    used.add(key);
    const mul = rndF(tpl.mul[0], tpl.mul[1]);
    prices[loc][rid] = Math.max(1, Math.round(RESOURCE_BASE[rid] * mul));
    news.push({ loc, res:rid, kind:tpl.kind, text: tpl.tpl(TRADER_NAMES[loc], RESOURCE_NAMES[rid]) });
  }
  market.prices = prices;
  market.news = news;
  market.nextAt = Date.now() + MARKET_PERIOD_MS;
  persistMarket();
}
// Single-flight guard — prevents concurrent regenMarket calls from racing on persist. (M1)
function ensureMarket() {
  if (market._regenerating) return;
  if (!market.prices || !Object.keys(market.prices).length || Date.now() >= market.nextAt) {
    market._regenerating = true;
    try { regenMarket(); }
    finally { market._regenerating = false; }
  }
}

app.get('/api/market', (_req, res) => {
  ensureMarket();
  res.json(snapshotMarket());
});

function sanitizeResources(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const rid of RESOURCE_IDS) {
    const v = Number(raw[rid]);
    if (Number.isFinite(v) && v > 0) out[rid] = Math.min(999999, Math.floor(v));
  }
  return out;
}

app.get('/api/inventory', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT resources FROM player_data WHERE user_id = $1`,
      [req.user.uid]
    );
    if (!r.rowCount) return res.status(404).json({ error: 'no player' });
    res.json({ resources: sanitizeResources(r.rows[0].resources) });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/inventory/credit', auth, async (req, res) => {
  const uid = req.user.uid;
  const now = Date.now();
  const rec = creditRate.get(uid) || { windowStart: now, count: 0, units: 0 };
  if (now - rec.windowStart > CREDIT_RATE_WINDOW_MS) { rec.windowStart = now; rec.count = 0; rec.units = 0; }
  rec.count++;
  creditRate.set(uid, rec);
  if (rec.count > CREDIT_RATE_MAX) return res.status(429).json({ error: 'rate limit' });

  const drops = req.body?.drops || {};
  const clean = {};
  let total = 0;
  for (const rid of RESOURCE_IDS) {
    const v = Number(drops[rid]);
    if (Number.isFinite(v) && v > 0) {
      const n = Math.min(MAX_CREDIT_PER_CALL, Math.floor(v));
      clean[rid] = n;
      total += n;
    }
  }
  if (!total) return res.json({ ok:true, resources: {}, credited: {} });

  // Per-minute units cap, scaled by player level.
  const lvlRow = await pool.query(`SELECT lvl FROM player_data WHERE user_id = $1`, [uid]);
  const lvl = Math.max(1, lvlRow.rows[0]?.lvl|0);
  const unitsCap = CREDIT_TOTAL_PER_MIN_BASE + CREDIT_TOTAL_PER_MIN_PER_LVL * lvl;
  if ((rec.units|0) + total > unitsCap) {
    return res.status(429).json({ error: 'rate limit', units_left: Math.max(0, unitsCap - rec.units) });
  }
  rec.units = (rec.units|0) + total;
  creditRate.set(uid, rec);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = await client.query(
      `SELECT resources FROM player_data WHERE user_id = $1 FOR UPDATE`,
      [uid]
    );
    if (!cur.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'no player' }); }
    const have = sanitizeResources(cur.rows[0].resources);
    for (const rid of Object.keys(clean)) have[rid] = (have[rid]|0) + clean[rid];
    await client.query(
      `UPDATE player_data SET resources = $1::jsonb, updated_at = NOW() WHERE user_id = $2`,
      [JSON.stringify(have), uid]
    );
    await client.query('COMMIT');
    res.json({ ok:true, resources: have, credited: clean });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('credit error:', e);
    res.status(500).json({ error: 'db error' });
  } finally {
    client.release();
  }
});

app.post('/api/market/trade', auth, async (req, res) => {
  ensureMarket();
  const { loc, rid, qty, action } = req.body || {};
  if (!LOCATION_IDS.includes(loc) || !RESOURCE_IDS.includes(rid)) {
    return res.status(400).json({ error: 'bad payload' });
  }
  if (action !== 'buy' && action !== 'sell') {
    return res.status(400).json({ error: 'bad action' });
  }
  const n = Math.max(1, Math.min(MAX_TRADE_QTY, parseInt(qty)|0));
  const price = market.prices[loc][rid]|0;
  const total = price * n;

  return withTradeLock(`${loc}:${rid}`, () => tradeOnce());

  async function tradeOnce() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const pr = await client.query(
      `SELECT GREATEST(0, gold + pending_gold_delta) AS eff, resources
         FROM player_data WHERE user_id = $1 FOR UPDATE`,
      [req.user.uid]
    );
    if (!pr.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'no player' });
    }
    const eff = pr.rows[0].eff|0;
    const resources = sanitizeResources(pr.rows[0].resources);

    if (action === 'buy') {
      const have = market.stock[loc][rid]|0;
      if (have < n) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'out of stock', stock: have, price, market: snapshotMarket() });
      }
      if (eff < total) {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'no gold', need: total, have: eff, market: snapshotMarket() });
      }
      resources[rid] = (resources[rid]|0) + n;
      // Materialize: commit new gold directly and zero out pending so /api/save
      // can't double-apply the deduction via its gold+pending merge.
      await client.query(
        `UPDATE player_data
            SET gold = GREATEST(0, gold + pending_gold_delta - $1),
                pending_gold_delta = 0,
                resources = $2::jsonb,
                updated_at = NOW()
          WHERE user_id = $3`,
        [total, JSON.stringify(resources), req.user.uid]
      );
      market.stock[loc][rid] = have - n;
      await client.query('COMMIT');
      persistMarket();
      return res.json({ ok:true, action, loc, rid, qty:n, price, total, gold: eff - total, resources, market: snapshotMarket() });
    }

    // sell
    const owned = resources[rid]|0;
    if (owned < n) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'no resource', have: owned, need: n, resources, market: snapshotMarket() });
    }
    resources[rid] = owned - n;
    if (resources[rid] <= 0) delete resources[rid];
    await client.query(
      `UPDATE player_data
          SET gold = GREATEST(0, gold + pending_gold_delta + $1),
              pending_gold_delta = 0,
              resources = $2::jsonb,
              updated_at = NOW()
        WHERE user_id = $3`,
      [total, JSON.stringify(resources), req.user.uid]
    );
    market.stock[loc][rid] = (market.stock[loc][rid]|0) + n;
    await client.query('COMMIT');
    persistMarket();
    return res.json({ ok:true, action, loc, rid, qty:n, price, total, gold: eff + total, resources, market: snapshotMarket() });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('trade error:', e);
    return res.status(500).json({ error: 'db error' });
  } finally {
    client.release();
  }
  }
});

// ==================== VILLAGE FEED ====================
const villageFeed = [];
const FEED_TTL_MS = 300000;
const FEED_MAX = 120;
function emitFeed(text, actorId = null, victimId = null, kind = null) {
  villageFeed.push({ t: Date.now(), text, actor: actorId, victim: victimId, kind });
  const cutoff = Date.now() - FEED_TTL_MS;
  while (villageFeed.length && villageFeed[0].t < cutoff) villageFeed.shift();
  if (villageFeed.length > FEED_MAX) villageFeed.splice(0, villageFeed.length - FEED_MAX);
}
const FEED_ENTER = [
  a => `${a} выходит на песок арены, бряцая оружием.`,
  a => `${a} ступает в круг арены — взгляд холоден.`,
  a => `${a} бросает вызов всем, кто на арене.`,
  a => `${a} появляется у ворот арены под ропот толпы.`,
  a => `${a} обнажает клинок и вступает на арену.`,
];
const FEED_LEAVE = [
  a => `${a} покидает арену, зализывая раны.`,
  a => `${a} исчезает в тени ворот арены.`,
  a => `${a} уходит с арены, не глядя назад.`,
  a => `${a} растворяется в пыли арены.`,
  a => `${a} отступает с арены — видимо, хватило на сегодня.`,
];
const FEED_KILL = [
  (a,b) => `${a} сокрушает ${b} на арене.`,
  (a,b) => `Клинок ${a} находит сердце ${b}.`,
  (a,b) => `${a} отправляет ${b} в небытие.`,
  (a,b) => `${a} вписывает имя ${b} в список павших.`,
  (a,b) => `${a} повергает ${b} в прах.`,
  (a,b) => `${a} ставит точку в судьбе ${b}.`,
  (a,b) => `На арене пал ${b} от клинка ${a}.`,
  (a,b) => `${a} одерживает верх над ${b} в кровавой схватке.`,
  (a,b) => `${b} не устоял против ${a} — арена запомнит.`,
  (a,b) => `${a} обращает ${b} в тень и пыль.`,
];
function pickTpl(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

const FEED_DEDUP_MS = 300000;
const feedLastEmit = new Map(); // key = `${kind}:${uid}` -> timestamp
function feedThrottle(kind, uid) {
  const k = `${kind}:${uid}`;
  const now = Date.now();
  const last = feedLastEmit.get(k) || 0;
  if (now - last < FEED_DEDUP_MS) return false;
  feedLastEmit.set(k, now);
  return true;
}

// ==================== PVP ARENA (server-authoritative real-time) ====================
const arena = new Map(); // userId -> combat state
const ARENA_TIMEOUT_MS = 60000;
const ATTACK_CD_MS = 1200;
const REGEN_TICK_MS = 2500;
const CORPSE_LINGER_MS = 4000;
const SPELL_CD_MS = 30000;
const RESPAWN_CD_MS = 10000;       // minimum time after death before re-entering
const ARENA_ACTION_MIN_MS = 80;    // per-uid min interval between /arena/action calls
const ARENA_STATE_MIN_MS = 250;    // per-uid min interval between /arena/state polls

const SPELLS = {
  fireball:   { cost:12, dmg:[14,22] },
  iceshard:   { cost:8,  dmg:[9,15] },
  lightning:  { cost:18, dmg:[22,32], aoe:'chain', chain:0.6 },
  frostnova:  { cost:22, dmg:[16,24], aoe:'all',   mult:0.7 },
  heal:       { cost:10, heal:[18,28] },
  poison:     { cost:6,  dmg:[10,16] },
  shadow:     { cost:14, dmg:[18,28] },
  smokebomb:  { cost:16, dmg:[10,16], aoe:'all',   mult:0.5 },
  rage:       { cost:8,  dmg:[12,20] },
  cleave:     { cost:14, dmg:[20,30], aoe:'chain', chain:0.5 },
  whirlwind:  { cost:22, dmg:[18,28], aoe:'all',   mult:0.6 },
};
function spellMul(spellLvl, key) { return 1 + 0.2 * ((spellLvl && spellLvl[key]) || 0); }
function rndI(a, b) { return a + Math.floor(Math.random() * (b - a + 1)); }
function applyDamage(tgt, now, dmg) {
  dmg = Math.max(1, Math.floor(dmg));
  tgt.hp = Math.max(0, tgt.hp - dmg);
  return dmg;
}

// Cap per-player event buffer so a laggy client can't let it grow unbounded.
const INCOMING_BUFFER_MAX = 32;
function pushIncoming(target, ev) {
  if (!target) return;
  if (!target.incoming) target.incoming = [];
  target.incoming.push(ev);
  if (target.incoming.length > INCOMING_BUFFER_MAX) {
    target.incoming.splice(0, target.incoming.length - INCOMING_BUFFER_MAX);
  }
}

function arenaPrune() {
  const now = Date.now();
  for (const [id, p] of arena) {
    if (p.dead && now - p.deathAt > CORPSE_LINGER_MS) { arena.delete(id); continue; }
    if (!p.dead && now - p.lastSeen > ARENA_TIMEOUT_MS) {
      arena.delete(id);
      if (feedThrottle('leave', id)) emitFeed(pickTpl(FEED_LEAVE)(p.username), id, null, 'leave');
    }
  }
}
function tickRegen(p, now) {
  if (p.dead) return;
  if (now - p.lastRegen < REGEN_TICK_MS) return;
  const steps = Math.floor((now - p.lastRegen) / REGEN_TICK_MS);
  p.lastRegen += steps * REGEN_TICK_MS;
  p.hp = Math.min(p.hpMax, p.hp + steps * Math.max(1, Math.round(p.hpMax * 0.02)));
  p.mp = Math.min(p.mpMax, p.mp + steps * Math.max(1, Math.round(p.mpMax * 0.05)));
}
function arenaListFor(uid) {
  const list = [];
  for (const [id, p] of arena) {
    if (id === uid) continue;
    list.push({
      id, username: p.username, cls: p.cls, lvl: p.lvl,
      hp: p.hp, hpMax: p.hpMax,
      dead: !!p.dead,
    });
  }
  return list;
}

// Central arena ticker — runs prune + regen once per second for everyone,
// so /api/arena/state handlers stay O(N) only in map iteration (no per-player work).
setInterval(() => {
  const now = Date.now();
  arenaPrune();
  for (const p of arena.values()) tickRegen(p, now);
}, 1000).unref();

// Periodic cleanup of per-user bookkeeping maps to prevent unbounded growth.
setInterval(() => {
  const now = Date.now();
  for (const [k, rec] of creditRate) {
    if (now - rec.windowStart > CREDIT_RATE_WINDOW_MS * 2) creditRate.delete(k);
  }
  for (const [k, t] of feedLastEmit) {
    if (now - t > FEED_DEDUP_MS * 2) feedLastEmit.delete(k);
  }
  // B3: prune lastDeathAt — entries older than respawn CD × 10 are useless.
  const deathCutoff = now - RESPAWN_CD_MS * 10;
  for (const [uid, t] of lastDeathAt) if (t < deathCutoff) lastDeathAt.delete(uid);
}, 60000).unref();
function sanitizeSpellLvl(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const out = {};
  for (const k of Object.keys(SPELLS)) {
    const v = Number(raw[k]);
    if (Number.isFinite(v) && v > 0) out[k] = Math.max(0, Math.min(20, v|0));
  }
  return out;
}

function sanitizeStats(s, lvl = 1) {
  const clamp = (v, lo, hi, d) => {
    const n = Number(v); if (!Number.isFinite(n)) return d;
    return Math.max(lo, Math.min(hi, n));
  };
  // Level-scaled caps so the client can't self-report absurd stats.
  const L = Math.max(1, lvl|0);
  const hpCap   = 120 + L * 40;    // lvl 1 → 160, lvl 50 → 2120
  const mpCap   =  50 + L * 20;
  const statCap =  20 + L * 10;    // str/agi/int
  const armCap  =  10 + L * 8;
  const wdCap   =  10 + L * 6;
  const wd = Array.isArray(s?.wdmg) ? s.wdmg : [4, 8];
  return {
    hpMax: clamp(s?.hpMax, 30, hpCap,  80)|0,
    mpMax: clamp(s?.mpMax, 0,  mpCap,  30)|0,
    str:   clamp(s?.str,   0,  statCap, 5)|0,
    agi:   clamp(s?.agi,   0,  statCap, 5)|0,
    int_:  clamp(s?.int_ ?? s?.int, 0, statCap, 5)|0,
    armor: clamp(s?.armor, 0,  armCap,  0)|0,
    crit:  clamp(s?.crit,  0,  0.5,    0.05),
    wdmg:  [ clamp(wd[0], 1, wdCap, 4)|0, clamp(wd[1], 1, wdCap, 8)|0 ].sort((a,b)=>a-b),
  };
}

async function loadPlayerBase(uid) {
  const r = await pool.query(
    `SELECT u.username, p.cls, p.lvl, p.pvp_kills, p.pvp_stats, p.pvp_spell_lvl
     FROM users u JOIN player_data p ON p.user_id = u.id
     WHERE u.id = $1`,
    [uid]
  );
  return r.rowCount ? r.rows[0] : null;
}

// Track most recent death per uid so respawn cooldown survives corpse-linger cleanup.
const lastDeathAt = new Map();

// Per-uid lock for /arena/enter so concurrent enters can't reset hp/mp/cd (B6).
const enterLocks = new Map();
function withEnterLock(uid, fn) {
  const prev = enterLocks.get(uid) || Promise.resolve();
  const run = prev.then(fn, fn);
  const tail = run.catch(() => {});
  enterLocks.set(uid, tail);
  tail.then(() => { if (enterLocks.get(uid) === tail) enterLocks.delete(uid); });
  return run;
}

app.post('/api/arena/enter', auth, async (req, res) => {
  return withEnterLock(req.user.uid, async () => {
  try {
    const uid = req.user.uid;
    const now = Date.now();

    // P1: block re-entering while already alive on arena (prevents hp/mp/cd reset exploit).
    const cur = arena.get(uid);
    if (cur && !cur.dead) {
      cur.lastSeen = now;
      return res.status(409).json({ error: 'already on arena' });
    }
    // P2: respawn cooldown after death.
    const lastDeath = lastDeathAt.get(uid) || 0;
    if (lastDeath && now - lastDeath < RESPAWN_CD_MS) {
      return res.status(409).json({
        error: 'respawn cooldown',
        cd_ms: RESPAWN_CD_MS - (now - lastDeath),
      });
    }

    const base = await loadPlayerBase(uid);
    if (!base) return res.status(404).json({ error: 'not found' });

    // P5 + P10: authoritative stats & spell levels from DB (ignore request body).
    const stats = sanitizeStats(base.pvp_stats || {}, base.lvl|0);
    const spellLvl = sanitizeSpellLvl(base.pvp_spell_lvl) || {};

    const wasPresent = !!cur; // cur existed but was dead
    arena.set(uid, {
      username: base.username, cls: base.cls, lvl: base.lvl|0,
      hpMax: stats.hpMax, hp: stats.hpMax,
      mpMax: stats.mpMax, mp: stats.mpMax,
      str: stats.str, agi: stats.agi, int_: stats.int_,
      armor: stats.armor, crit: stats.crit, wdmg: stats.wdmg,
      spellLvl, spellCd: {},
      lastAttack: 0,
      lastRegen: now, lastSeen: now,
      lastActionAt: 0, lastStateAt: 0,
      dead: false, killedBy: null, deathAt: 0, _resolving: false,
      pvp_kills: base.pvp_kills|0,
      incoming: [],
    });
    if (!wasPresent && feedThrottle('enter', uid)) emitFeed(pickTpl(FEED_ENTER)(base.username), uid, null, 'enter');
    res.json({ ok: true });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'db error' });
  }
  });
});

app.post('/api/arena/leave', auth, (req, res) => {
  const p = arena.get(req.user.uid);
  if (p) {
    arena.delete(req.user.uid);
    if (!p.dead && feedThrottle('leave', req.user.uid)) emitFeed(pickTpl(FEED_LEAVE)(p.username), req.user.uid, null, 'leave');
  }
  res.json({ ok: true });
});

app.post('/api/arena/leave-beacon',
  express.text({ type: '*/*', limit: '4kb' }),
  (req, res) => {
    let t = null;
    if (typeof req.body === 'string' && req.body) {
      try { t = JSON.parse(req.body)?.t || null; } catch { t = null; }
    } else if (req.body && typeof req.body === 'object') {
      t = req.body.t || null;
    }
    if (t) {
      try {
        const u = jwt.verify(t, JWT_SECRET);
        const p = arena.get(u.uid);
        if (p) {
          arena.delete(u.uid);
          if (!p.dead && feedThrottle('leave', u.uid)) emitFeed(pickTpl(FEED_LEAVE)(p.username), u.uid, null, 'leave');
        }
      } catch {}
    }
    res.status(204).end();
  }
);

app.get('/api/village/feed', auth, (req, res) => {
  const since = Math.max(0, Number(req.query.since) || 0);
  const uid = req.user.uid;
  const events = villageFeed
    .filter(ev => {
      if (ev.t <= since) return false;
      // Filter out events where current user is participant — they already see these locally. (P8)
      return ev.actor !== uid && ev.victim !== uid;
    })
    .map(ev => ({ t: ev.t, text: ev.text, kind: ev.kind || null }));
  res.json({ events, now: Date.now() });
});

async function resolveKill(winnerId, loserId) {
  lastDeathAt.set(loserId, Date.now()); // enforced regardless of DB outcome (P2)
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // P3: lock both rows atomically in a deterministic order to avoid cross-kill deadlocks.
    const lockRows = await client.query(
      `SELECT user_id, GREATEST(0, gold + pending_gold_delta) AS eff
         FROM player_data
        WHERE user_id IN ($1, $2)
        ORDER BY user_id
          FOR UPDATE`,
      [winnerId, loserId]
    );
    if (lockRows.rowCount < 2) {
      await client.query('ROLLBACK');
      return { transfer: 0, error: true };
    }
    const loserRow = lockRows.rows.find(r => r.user_id === loserId);
    const transfer = Math.floor((loserRow?.eff|0) * 0.05);

    if (transfer > 0) {
      await client.query(
        `UPDATE player_data SET pending_gold_delta = pending_gold_delta - $1, updated_at = NOW()
         WHERE user_id = $2`,
        [transfer, loserId]
      );
    }
    const w = await client.query(
      `UPDATE player_data SET gold = GREATEST(0, gold + pending_gold_delta + $1),
           pending_gold_delta = 0,
           pvp_kills = pvp_kills + 1, updated_at = NOW()
       WHERE user_id = $2 RETURNING pvp_kills`,
      [transfer, winnerId]
    );
    await client.query('COMMIT');

    const winnerName = (arena.get(winnerId) || {}).username
      || (await pool.query(`SELECT username FROM users WHERE id=$1`, [winnerId])).rows[0]?.username || 'кто-то';
    const loserName  = (arena.get(loserId) || {}).username
      || (await pool.query(`SELECT username FROM users WHERE id=$1`, [loserId])).rows[0]?.username || 'кто-то';
    emitFeed(pickTpl(FEED_KILL)(winnerName, loserName), winnerId, loserId, 'kill');
    return { transfer, pvp_kills: w.rows[0]?.pvp_kills|0, winnerName, loserName };
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('resolveKill error:', e);
    return { transfer: 0, error: true };
  } finally {
    client.release();
  }
}

function parseTargetId(raw) {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

// Count live opponents excluding self — used to guard AoE-all from wasting mana on empty arena.
function liveOpponentCount(uid) {
  let c = 0;
  for (const [id, p] of arena) if (id !== uid && !p.dead) c++;
  return c;
}

// Try to atomically claim a kill on target — only the first attacker past this gate
// proceeds to resolveKill, protecting against double-payout on concurrent finishing blows. (P6)
function claimKill(target, attackerId, now) {
  if (target._resolving || target.dead) return false;
  target._resolving = true;
  target.dead = true;
  target.killedBy = attackerId;
  target.deathAt = now;
  return true;
}

app.post('/api/arena/action', auth, async (req, res) => {
  const me = req.user.uid;
  const type = String(req.body?.type || '');
  const now = Date.now();
  const self = arena.get(me);
  if (!self) return res.status(409).json({ error: 'not on arena' });
  if (self.dead) return res.status(409).json({ error: 'dead', killedBy: self.killedBy });

  // P7: per-uid min-interval rate limit.
  if (now - (self.lastActionAt || 0) < ARENA_ACTION_MIN_MS) {
    return res.status(429).json({ error: 'too fast' });
  }
  self.lastActionAt = now;
  self.lastSeen = now;
  tickRegen(self, now);

  if (type === 'leave') {
    arena.delete(me);
    if (feedThrottle('leave', me)) emitFeed(pickTpl(FEED_LEAVE)(self.username), me, null, 'leave');
    return res.json({ ok: true, left: true });
  }
  if (type === 'attack') {
    const tid = parseTargetId(req.body?.target_id);
    if (!tid || tid === me) return res.status(400).json({ error: 'bad target' });
    const tgt = arena.get(tid);
    if (!tgt || tgt.dead) return res.status(409).json({ error: 'target gone' });
    if (now - self.lastAttack < ATTACK_CD_MS) {
      return res.json({ ok: false, reason: 'cd', cd_ms: ATTACK_CD_MS - (now - self.lastAttack) });
    }
    self.lastAttack = now;
    tickRegen(tgt, now);
    const dodge = Math.min(0.35, tgt.agi * 0.012);
    if (Math.random() < dodge) {
      pushIncoming(tgt, { kind:'miss', by: me, byName: self.username, at: now });
      return res.json({ ok: true, attack: { dodged: true, target_id: tid } });
    }
    let dmg = Math.floor(rndF(self.wdmg[0], self.wdmg[1]) + self.str / 2);
    const crit = Math.random() < self.crit;
    if (crit) dmg = Math.floor(dmg * 1.7);
    dmg = Math.max(1, dmg - Math.floor(tgt.armor / 2));
    tgt.hp = Math.max(0, tgt.hp - dmg);
    pushIncoming(tgt, { kind:'attack', by: me, byName: self.username, dmg, crit, at: now });
    let kill = null;
    if (tgt.hp <= 0 && claimKill(tgt, me, now)) {
      const r = await resolveKill(me, tid);
      if (r.pvp_kills|0) self.pvp_kills = r.pvp_kills|0;
      kill = { target_id: tid, transfer: r.transfer|0, pvp_kills: self.pvp_kills };
    }
    return res.json({ ok: true, attack: { dmg, crit, target_id: tid, target_hp: tgt.hp, target_hpMax: tgt.hpMax, kill } });
  }
  if (type === 'cast') {
    const key = String(req.body?.spell || '');
    const sp = SPELLS[key];
    if (!sp) return res.status(400).json({ error: 'bad spell' });
    const cdAt = self.spellCd[key] || 0;
    if (cdAt > now) return res.json({ ok: false, reason: 'cd', cd_ms: cdAt - now });
    if (self.mp < sp.cost) return res.json({ ok: false, reason: 'mp' });

    // Pre-flight validation so we never charge mana for an action that can't land.
    const tid = parseTargetId(req.body?.target_id);
    const primary = tid && tid !== me ? arena.get(tid) : null;
    if (!sp.heal) {
      if (sp.aoe === 'all') {
        if (liveOpponentCount(me) === 0) return res.json({ ok: false, reason: 'no target' }); // P4
      } else if (sp.aoe === 'chain') {
        if (!primary || primary.dead) return res.json({ ok: false, reason: 'no target' });
      } else {
        if (!primary || primary.dead) return res.json({ ok: false, reason: 'no target' });
      }
    }

    self.mp -= sp.cost;
    self.spellCd[key] = now + SPELL_CD_MS;
    const mul = spellMul(self.spellLvl, key);

    if (sp.heal) {
      const h = Math.ceil((rndI(sp.heal[0], sp.heal[1]) + self.int_) * mul);
      self.hp = Math.min(self.hpMax, self.hp + h);
      return res.json({ ok: true, cast: { spell: key, mp_cost: sp.cost, heal: h, self_hp: self.hp, self_mp: self.mp, cd_until: self.spellCd[key] } });
    }

    const base = Math.ceil((rndI(sp.dmg[0], sp.dmg[1]) + self.int_) * mul);
    const hits = [];
    const killedTargets = [];

    function doHit(targetId, target, dmg) {
      if (target.dead) return;
      tickRegen(target, now);
      const dodge = Math.min(0.35, target.agi * 0.012);
      if (Math.random() < dodge) {
        hits.push({ target_id: targetId, dodged: true });
        pushIncoming(target, { kind:'miss', by: me, byName: self.username, spell: key, at: now });
        return;
      }
      const applied = applyDamage(target, now, dmg);
      const hit = { target_id: targetId, dmg: applied, hp: target.hp, hpMax: target.hpMax };
      pushIncoming(target, { kind:'spell', by: me, byName: self.username, spell: key, dmg: applied, at: now });
      if (target.hp <= 0 && claimKill(target, me, now)) {
        killedTargets.push(targetId);
        hit.dead = true;
      }
      hits.push(hit);
    }

    if (sp.aoe === 'all') {
      const dealt = Math.max(1, Math.floor(base * (sp.mult || 0.7)));
      for (const [id, p] of arena) {
        if (id === me || p.dead) continue;
        doHit(id, p, dealt);
      }
    } else if (sp.aoe === 'chain') {
      doHit(tid, primary, base);
      const splash = Math.max(1, Math.floor(base * (sp.chain || 0.5)));
      for (const [id, p] of arena) {
        if (id === me || id === tid || p.dead) continue;
        doHit(id, p, splash);
      }
    } else {
      doHit(tid, primary, base);
    }

    const killResults = [];
    for (const loserId of killedTargets) {
      const r = await resolveKill(me, loserId);
      killResults.push({ target_id: loserId, transfer: r.transfer|0, pvp_kills: r.pvp_kills|0 });
      if (r.pvp_kills|0) self.pvp_kills = r.pvp_kills|0;
    }
    return res.json({
      ok: true,
      cast: {
        spell: key, mp_cost: sp.cost, self_mp: self.mp,
        cd_until: self.spellCd[key],
        hits, kills: killResults, pvp_kills: self.pvp_kills,
      },
    });
  }
  return res.status(400).json({ error: 'bad action' });
});

app.get('/api/arena/state', auth, (req, res) => {
  const me = req.user.uid;
  const self = arena.get(me);
  const now = Date.now();
  if (self) {
    if (now - (self.lastStateAt || 0) < ARENA_STATE_MIN_MS) {
      return res.status(429).json({ error: 'too fast' });
    }
    self.lastStateAt = now;
    self.lastSeen = now;
  }
  let incoming = [];
  if (self && self.incoming && self.incoming.length) {
    incoming = self.incoming;
    self.incoming = [];
  }
  const meOut = self ? {
    present: true,
    hp: self.hp, hpMax: self.hpMax,
    mp: self.mp, mpMax: self.mpMax,
    dead: !!self.dead,
    killedBy: self.killedBy,
    attackReadyAt: self.lastAttack + ATTACK_CD_MS,
    pvp_kills: self.pvp_kills,
    username: self.username,
    spellCd: self.spellCd || {},
    incoming,
  } : { present: false };
  res.json({ me: meOut, players: arenaListFor(me), now });
});

const LEADERBOARD_TTL_MS = 10000;
let leaderboardCache = { at: 0, data: null, inflight: null };
async function fetchLeaderboard() {
  const r = await pool.query(
    `SELECT u.username AS nick, p.cls, p.lvl, p.stage_max,
            GREATEST(0, p.gold + p.pending_gold_delta) AS gold,
            p.bosses, p.pvp_kills, p.updated_at
     FROM player_data p JOIN users u ON u.id = p.user_id
     ORDER BY p.lvl DESC, p.stage_max DESC, p.gold DESC, p.bosses DESC
     LIMIT 50`
  );
  return r.rows;
}
app.get('/api/leaderboard', async (_req, res) => {
  try {
    const now = Date.now();
    if (leaderboardCache.data && now - leaderboardCache.at < LEADERBOARD_TTL_MS) {
      return res.json(leaderboardCache.data);
    }
    if (!leaderboardCache.inflight) {
      leaderboardCache.inflight = fetchLeaderboard()
        .then(data => { leaderboardCache = { at: Date.now(), data, inflight: null }; return data; })
        .catch(e => { leaderboardCache.inflight = null; throw e; });
    }
    const data = await leaderboardCache.inflight;
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
  }
});

let httpServer = null;
async function shutdown(sig) {
  console.log(`[shutdown] ${sig} received, flushing…`);
  try { await flushMarket(); } catch {}
  if (httpServer) await new Promise(r => httpServer.close(r));
  try { await pool.end(); } catch {}
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

initDb()
  .then(() => loadMarket())
  .then(() => { httpServer = app.listen(PORT, () => console.log(`server listening on :${PORT}`)); })
  .catch(e => { console.error('fatal init error:', e); process.exit(1); });
