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
    CREATE TABLE IF NOT EXISTS app_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
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
const market = { prices:{}, stock:{}, news:[], nextAt:0 };
for (const loc of LOCATION_IDS) market.stock[loc] = Object.fromEntries(RESOURCE_IDS.map(r=>[r,0]));

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
}
function ensureMarket() {
  if (!market.prices || !Object.keys(market.prices).length || Date.now() >= market.nextAt) regenMarket();
}

app.get('/api/market', (_req, res) => {
  ensureMarket();
  res.json({ prices: market.prices, stock: market.stock, news: market.news, nextAt: market.nextAt });
});

app.post('/api/market/trade', auth, (req, res) => {
  ensureMarket();
  const { loc, rid, qty, action } = req.body || {};
  if (!LOCATION_IDS.includes(loc) || !RESOURCE_IDS.includes(rid)) return res.status(400).json({ error: 'bad payload' });
  const n = Math.max(1, Math.min(9999, parseInt(qty)|0));
  const price = market.prices[loc][rid];
  if (action === 'buy') {
    const have = market.stock[loc][rid] || 0;
    if (have < n) return res.status(409).json({ error: 'out of stock', stock: have, price, market: { prices: market.prices, stock: market.stock, news: market.news, nextAt: market.nextAt } });
    market.stock[loc][rid] = have - n;
    return res.json({ ok:true, action, loc, rid, qty:n, price, total: price*n, market: { prices: market.prices, stock: market.stock, news: market.news, nextAt: market.nextAt } });
  } else if (action === 'sell') {
    market.stock[loc][rid] = (market.stock[loc][rid]||0) + n;
    return res.json({ ok:true, action, loc, rid, qty:n, price, total: price*n, market: { prices: market.prices, stock: market.stock, news: market.news, nextAt: market.nextAt } });
  }
  return res.status(400).json({ error: 'bad action' });
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
