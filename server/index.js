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
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS pvp_kills INT NOT NULL DEFAULT 0;
  `);
  await pool.query(`
    ALTER TABLE player_data ADD COLUMN IF NOT EXISTS pending_gold_delta INT NOT NULL DEFAULT 0;
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
  // one-time test-data wipe — runs once, flag prevents reruns
  const wipeKey = 'wipe_testdata_2026_04_14';
  const w = await pool.query(`SELECT value FROM app_meta WHERE key = $1`, [wipeKey]);
  if (!w.rowCount) {
    const before = await pool.query(`SELECT COUNT(*)::int AS n FROM users`);
    await pool.query(`TRUNCATE TABLE users RESTART IDENTITY CASCADE`);
    await pool.query(
      `INSERT INTO app_meta (key, value) VALUES ($1, $2)`,
      [wipeKey, new Date().toISOString()]
    );
    console.log(`[init] test data wiped: ${before.rows[0].n} user(s) removed`);
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
    await pool.query(
      `UPDATE player_data
       SET gold = GREATEST(0, gold + pending_gold_delta), pending_gold_delta = 0
       WHERE user_id = $1 AND pending_gold_delta <> 0`,
      [req.user.uid]
    );
    const r = await pool.query(
      `SELECT u.username, p.cls, p.lvl, p.stage_max, p.gold, p.bosses, p.pvp_kills, p.save_blob, p.updated_at
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

app.delete('/api/me', auth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM users WHERE id = $1`, [req.user.uid]);
    res.json({ ok: true });
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
    const r = await pool.query(
      `INSERT INTO player_data (user_id, cls, lvl, stage_max, gold, bosses, save_blob, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
         cls = COALESCE(EXCLUDED.cls, player_data.cls),
         lvl = EXCLUDED.lvl,
         stage_max = EXCLUDED.stage_max,
         gold = GREATEST(0, EXCLUDED.gold + player_data.pending_gold_delta),
         bosses = EXCLUDED.bosses,
         save_blob = EXCLUDED.save_blob,
         pending_gold_delta = 0,
         updated_at = NOW()
       RETURNING gold, pvp_kills`,
      [req.user.uid, cls || null, lvl|0, stage_max|0, gold|0, bosses|0, save_blob || null]
    );
    const row = r.rows[0] || {};
    res.json({ ok: true, gold: row.gold|0, pvp_kills: row.pvp_kills|0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'db error' });
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
const MAX_TRADE_QTY = 500;
const market = { prices:{}, stock:{}, news:[], nextAt:0, loaded:false };
for (const loc of LOCATION_IDS) market.stock[loc] = Object.fromEntries(RESOURCE_IDS.map(r=>[r,0]));

function snapshotMarket() {
  return { prices: market.prices, stock: market.stock, news: market.news, nextAt: market.nextAt };
}
async function persistMarket() {
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
function ensureMarket() {
  if (!market.prices || !Object.keys(market.prices).length || Date.now() >= market.nextAt) regenMarket();
}

app.get('/api/market', (_req, res) => {
  ensureMarket();
  res.json(snapshotMarket());
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

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const pr = await client.query(
      `SELECT GREATEST(0, gold + pending_gold_delta) AS eff
         FROM player_data WHERE user_id = $1 FOR UPDATE`,
      [req.user.uid]
    );
    if (!pr.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'no player' });
    }
    const eff = pr.rows[0].eff|0;

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
      await client.query(
        `UPDATE player_data
            SET pending_gold_delta = pending_gold_delta - $1, updated_at = NOW()
          WHERE user_id = $2`,
        [total, req.user.uid]
      );
      market.stock[loc][rid] = have - n;
      await client.query('COMMIT');
      persistMarket();
      return res.json({ ok:true, action, loc, rid, qty:n, price, total, gold: eff - total, market: snapshotMarket() });
    }

    // sell
    await client.query(
      `UPDATE player_data
          SET pending_gold_delta = pending_gold_delta + $1, updated_at = NOW()
        WHERE user_id = $2`,
      [total, req.user.uid]
    );
    market.stock[loc][rid] = (market.stock[loc][rid]|0) + n;
    await client.query('COMMIT');
    persistMarket();
    return res.json({ ok:true, action, loc, rid, qty:n, price, total, gold: eff + total, market: snapshotMarket() });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    console.error('trade error:', e);
    return res.status(500).json({ error: 'db error' });
  } finally {
    client.release();
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
  arenaPrune();
  const now = Date.now();
  const list = [];
  for (const [id, p] of arena) {
    if (id === uid) continue;
    tickRegen(p, now);
    list.push({
      id, username: p.username, cls: p.cls, lvl: p.lvl,
      hp: p.hp, hpMax: p.hpMax,
      dead: !!p.dead,
    });
  }
  return list;
}
function sanitizeStats(s) {
  const clamp = (v, lo, hi, d) => {
    const n = Number(v); if (!Number.isFinite(n)) return d;
    return Math.max(lo, Math.min(hi, n));
  };
  const wd = Array.isArray(s?.wdmg) ? s.wdmg : [4, 8];
  return {
    hpMax: clamp(s?.hpMax, 30, 5000, 80)|0,
    mpMax: clamp(s?.mpMax, 0, 2000, 30)|0,
    str:   clamp(s?.str,   0, 2000, 5)|0,
    agi:   clamp(s?.agi,   0, 2000, 5)|0,
    int_:  clamp(s?.int_ ?? s?.int, 0, 2000, 5)|0,
    armor: clamp(s?.armor, 0, 2000, 0)|0,
    crit:  clamp(s?.crit,  0, 0.8, 0.05),
    wdmg:  [ clamp(wd[0], 1, 9999, 4)|0, clamp(wd[1], 1, 9999, 8)|0 ].sort((a,b)=>a-b),
  };
}

async function loadPlayerBase(uid) {
  const r = await pool.query(
    `SELECT u.username, p.cls, p.lvl, p.pvp_kills
     FROM users u JOIN player_data p ON p.user_id = u.id
     WHERE u.id = $1`,
    [uid]
  );
  return r.rowCount ? r.rows[0] : null;
}

app.post('/api/arena/enter', auth, async (req, res) => {
  try {
    const base = await loadPlayerBase(req.user.uid);
    if (!base) return res.status(404).json({ error: 'not found' });
    const stats = sanitizeStats(req.body?.stats || {});
    const now = Date.now();
    const wasPresent = arena.has(req.user.uid) && !arena.get(req.user.uid).dead;
    const rawSl = req.body?.spellLvl || {};
    const spellLvl = {};
    for (const k of Object.keys(SPELLS)) {
      const v = Number(rawSl[k]);
      if (Number.isFinite(v) && v > 0) spellLvl[k] = Math.max(0, Math.min(20, v|0));
    }
    arena.set(req.user.uid, {
      username: base.username, cls: base.cls, lvl: base.lvl|0,
      hpMax: stats.hpMax, hp: stats.hpMax,
      mpMax: stats.mpMax, mp: stats.mpMax,
      str: stats.str, agi: stats.agi, int_: stats.int_,
      armor: stats.armor, crit: stats.crit, wdmg: stats.wdmg,
      spellLvl, spellCd: {},
      lastAttack: 0,
      lastRegen: now, lastSeen: now,
      dead: false, killedBy: null, deathAt: 0,
      pvp_kills: base.pvp_kills|0,
    });
    if (!wasPresent && feedThrottle('enter', req.user.uid)) emitFeed(pickTpl(FEED_ENTER)(base.username), req.user.uid, null, 'enter');
    res.json({ ok: true });
  } catch (e) {
    console.error(e); res.status(500).json({ error: 'db error' });
  }
});

app.post('/api/arena/leave', auth, (req, res) => {
  const p = arena.get(req.user.uid);
  if (p) {
    arena.delete(req.user.uid);
    if (!p.dead && feedThrottle('leave', req.user.uid)) emitFeed(pickTpl(FEED_LEAVE)(p.username), req.user.uid, null, 'leave');
  }
  res.json({ ok: true });
});

app.post('/api/arena/leave-beacon', (req, res) => {
  const t = req.query.t;
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
});

app.get('/api/village/feed', auth, (req, res) => {
  const since = parseInt(req.query.since)|0;
  const uid = req.user.uid;
  const events = villageFeed
    .filter(ev => {
      if (ev.t <= since) return false;
      if (ev.kind === 'kill') return true;
      return ev.actor !== uid && ev.victim !== uid;
    })
    .map(ev => ({ t: ev.t, text: ev.text, kind: ev.kind || null }));
  res.json({ events, now: Date.now() });
});

async function resolveKill(winnerId, loserId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const lo = await client.query(
      `SELECT GREATEST(0, gold + pending_gold_delta) AS eff
       FROM player_data WHERE user_id = $1 FOR UPDATE`,
      [loserId]
    );
    if (!lo.rowCount) { await client.query('ROLLBACK'); return { transfer: 0 }; }
    const transfer = Math.floor((lo.rows[0].eff|0) * 0.05);
    await client.query(
      `UPDATE player_data SET pending_gold_delta = pending_gold_delta - $1, updated_at = NOW()
       WHERE user_id = $2`,
      [transfer, loserId]
    );
    const w = await client.query(
      `UPDATE player_data SET pending_gold_delta = pending_gold_delta + $1,
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
    console.error(e);
    return { transfer: 0, error: true };
  } finally {
    client.release();
  }
}

app.post('/api/arena/action', auth, async (req, res) => {
  const me = req.user.uid;
  const type = String(req.body?.type || '');
  const now = Date.now();
  const self = arena.get(me);
  if (!self) return res.status(409).json({ error: 'not on arena' });
  if (self.dead) return res.status(409).json({ error: 'dead', killedBy: self.killedBy });
  self.lastSeen = now;
  tickRegen(self, now);

  if (type === 'leave') {
    arena.delete(me);
    if (feedThrottle('leave', me)) emitFeed(pickTpl(FEED_LEAVE)(self.username), me, null, 'leave');
    return res.json({ ok: true, left: true });
  }
  if (type === 'attack') {
    const tid = parseInt(req.body?.target_id)|0;
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
      return res.json({ ok: true, attack: { dodged: true, target_id: tid } });
    }
    let dmg = Math.floor(rndF(self.wdmg[0], self.wdmg[1]) + self.str / 2);
    const crit = Math.random() < self.crit;
    if (crit) dmg = Math.floor(dmg * 1.7);
    dmg = Math.max(1, dmg - Math.floor(tgt.armor / 2));
    tgt.hp = Math.max(0, tgt.hp - dmg);
    let kill = null;
    if (tgt.hp <= 0) {
      tgt.dead = true;
      tgt.killedBy = me;
      tgt.deathAt = now;
      const r = await resolveKill(me, tid);
      self.pvp_kills = r.pvp_kills || self.pvp_kills;
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
    self.mp -= sp.cost;
    self.spellCd[key] = now + SPELL_CD_MS;
    const mul = spellMul(self.spellLvl, key);

    if (sp.heal) {
      const h = Math.ceil((rndI(sp.heal[0], sp.heal[1]) + self.int_) * mul);
      self.hp = Math.min(self.hpMax, self.hp + h);
      return res.json({ ok: true, cast: { spell: key, mp_cost: sp.cost, heal: h, self_hp: self.hp, self_mp: self.mp, cd_until: self.spellCd[key] } });
    }

    const tid = parseInt(req.body?.target_id)|0;
    const primary = tid && tid !== me ? arena.get(tid) : null;
    if (!primary && !sp.aoe) return res.json({ ok: false, reason: 'no target' });
    if (primary && primary.dead && !sp.aoe) return res.json({ ok: false, reason: 'no target' });

    const base = Math.ceil((rndI(sp.dmg[0], sp.dmg[1]) + self.int_) * mul);
    const hits = [];
    const kills = [];

    async function doHit(targetId, target, dmg) {
      tickRegen(target, now);
      const dodge = Math.min(0.35, target.agi * 0.012);
      if (Math.random() < dodge) { hits.push({ target_id: targetId, dodged: true }); return; }
      const applied = applyDamage(target, now, dmg);
      const hit = { target_id: targetId, dmg: applied, hp: target.hp, hpMax: target.hpMax };
      if (target.hp <= 0) {
        target.dead = true; target.killedBy = me; target.deathAt = now;
        kills.push(targetId); hit.dead = true;
      }
      hits.push(hit);
    }

    if (sp.aoe === 'all') {
      const dealt = Math.max(1, Math.floor(base * (sp.mult || 0.7)));
      for (const [id, p] of arena) {
        if (id === me || p.dead) continue;
        await doHit(id, p, dealt);
      }
    } else if (sp.aoe === 'chain') {
      if (!primary || primary.dead) { self.mp += sp.cost; self.spellCd[key] = cdAt; return res.json({ ok:false, reason:'no target' }); }
      await doHit(tid, primary, base);
      const splash = Math.max(1, Math.floor(base * (sp.chain || 0.5)));
      for (const [id, p] of arena) {
        if (id === me || id === tid || p.dead) continue;
        await doHit(id, p, splash);
      }
    } else {
      if (!primary || primary.dead) { self.mp += sp.cost; self.spellCd[key] = cdAt; return res.json({ ok:false, reason:'no target' }); }
      await doHit(tid, primary, base);
    }

    const killResults = [];
    for (const loserId of kills) {
      const r = await resolveKill(me, loserId);
      killResults.push({ target_id: loserId, transfer: r.transfer|0, pvp_kills: r.pvp_kills|0 });
      self.pvp_kills = r.pvp_kills || self.pvp_kills;
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
  if (self) { self.lastSeen = now; tickRegen(self, now); }
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
  } : { present: false };
  res.json({ me: meOut, players: arenaListFor(me), now });
});

app.get('/api/leaderboard', async (_req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.username AS nick, p.cls, p.lvl, p.stage_max,
              GREATEST(0, p.gold + p.pending_gold_delta) AS gold,
              p.bosses, p.pvp_kills, p.updated_at
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
  .then(() => loadMarket())
  .then(() => app.listen(PORT, () => console.log(`server listening on :${PORT}`)))
  .catch(e => { console.error('init failed', e); process.exit(1); });
