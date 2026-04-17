// Resolve UI mode (lite | rich) for the request.
// Priority: ?ui= query > ui= cookie > UA heuristic > default (rich).

const LITE_UA = /j2me|midp|series ?40|opera ?mini|opera ?mobi|ucbrowser.*mini|symbian|docomo|kddi|\bwap\b|obigo|sonyericsson|nokiac|nokia[0-9]|featurephone/i;

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    let v = part.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    try { v = decodeURIComponent(v); } catch {}
    if (k) out[k] = v;
  }
  return out;
}

export function readCookies(req) {
  if (!req._cookies) req._cookies = parseCookies(req.headers.cookie || '');
  return req._cookies;
}

export function pickUiMode(req) {
  const q = String(req.query?.ui || '').toLowerCase();
  if (q === 'lite' || q === 'rich') return q;
  const cookies = readCookies(req);
  if (cookies.ui === 'lite' || cookies.ui === 'rich') return cookies.ui;
  const ua = String(req.headers['user-agent'] || '');
  return LITE_UA.test(ua) ? 'lite' : 'rich';
}

export function uiModeMiddleware(req, _res, next) {
  req.uiMode = pickUiMode(req);
  next();
}

export function setUiCookie(res, mode) {
  if (mode !== 'lite' && mode !== 'rich') return;
  res.setHeader('Set-Cookie', `ui=${mode}; Path=/; Max-Age=31536000; SameSite=Lax`);
}

const SAFE_REDIRECT = /^\/[A-Za-z0-9/_\-?=&.%;:]*$/;
export function safeBackPath(raw, fallback = '/') {
  const s = typeof raw === 'string' ? raw : '';
  if (!s || !SAFE_REDIRECT.test(s)) return fallback;
  if (s.startsWith('//')) return fallback;
  return s;
}
