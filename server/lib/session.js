// Session support for the lite (no-JS / no-cookie) path.
// - Reads JWT from `sid` cookie OR a `;s=<token>` path parameter (jsessionid-style).
// - Offers issueSession(res, token) to set cookie on login.
// - urlFor(req, path) preserves `;s=` across links when cookies aren't available.
// - csrfToken(req) / requireCsrf for POST forms without JS.

import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

let _secret = null;
export function configureSession(secret) { _secret = secret || null; }

// Match `;s=<token>` anywhere in the path portion (before ?query or #frag).
// Token chars: JWT-safe set (base64url + '.').
const PATH_PARAM_RE = /^([^?#]*?);s=([A-Za-z0-9._\-%]+)([?#].*|\/.*|)$/;

// Strip `;s=<token>` from req.url before routing; stash token on the request.
export function stripSessionPathParam(req, _res, next) {
  const url = req.url;
  if (url && url.indexOf(';s=') !== -1) {
    const m = url.match(PATH_PARAM_RE);
    if (m) {
      try { req.urlSessionToken = decodeURIComponent(m[2]); }
      catch { req.urlSessionToken = m[2]; }
      req.url = m[1] + m[3];
      delete req._parsedUrl;
    }
  }
  next();
}

function readCookieToken(req) {
  const h = req.headers.cookie || '';
  if (!h) return null;
  for (const part of String(h).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k !== 'sid') continue;
    let v = part.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    try { return decodeURIComponent(v); } catch { return v; }
  }
  return null;
}

// Populate req.session / req.sessionToken / req.cookieless.
// Never fails — invalid tokens just yield no session.
export function sessionMiddleware(req, _res, next) {
  const cookieToken = readCookieToken(req);
  const urlToken = req.urlSessionToken || null;
  const token = cookieToken || urlToken;
  req.cookieless = !cookieToken && !!urlToken;
  req.sessionToken = null;
  req.session = null;
  if (!token || !_secret) return next();
  let payload;
  try { payload = jwt.verify(token, _secret); }
  catch { return next(); }
  req.sessionToken = token;
  req.session = { uid: payload.uid, username: payload.username, tv: payload.tv | 0 };
  next();
}

const COOKIE_MAX_AGE = 60 * 60 * 24 * 30; // 30 days

function appendSetCookie(res, value) {
  const prev = res.getHeader('Set-Cookie');
  if (!prev) res.setHeader('Set-Cookie', value);
  else if (Array.isArray(prev)) res.setHeader('Set-Cookie', [...prev, value]);
  else res.setHeader('Set-Cookie', [prev, value]);
}

export function issueSession(res, token) {
  const attrs = [
    'sid=' + encodeURIComponent(token),
    'Path=/',
    `Max-Age=${COOKIE_MAX_AGE}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (process.env.NODE_ENV === 'production') attrs.push('Secure');
  appendSetCookie(res, attrs.join('; '));
}

export function clearSession(res) {
  appendSetCookie(res, 'sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
}

// Build a URL, preserving `;s=<token>` when the client is cookieless.
export function urlFor(req, path) {
  if (typeof path !== 'string' || !path) return '/';
  if (!req || !req.cookieless || !req.sessionToken) return path;
  const q = path.indexOf('?');
  const f = path.indexOf('#');
  let cut = path.length;
  if (q >= 0) cut = Math.min(cut, q);
  if (f >= 0) cut = Math.min(cut, f);
  return path.slice(0, cut) + ';s=' + encodeURIComponent(req.sessionToken) + path.slice(cut);
}

// Deterministic CSRF token for the current session.
// Rotates on re-login (JWT changes) but is stable across page loads.
export function csrfToken(req) {
  if (!req || !req.sessionToken || !_secret) return '';
  return crypto.createHmac('sha256', _secret)
    .update('csrf|' + req.sessionToken)
    .digest('hex')
    .slice(0, 32);
}

export function requireCsrf(req, res, next) {
  if (!req.session) return res.status(403).type('text/plain').send('no session');
  const expected = csrfToken(req);
  const given = String(req.body?._csrf || req.query?._csrf || '');
  if (!expected || given.length !== expected.length) {
    return res.status(403).type('text/plain').send('bad csrf');
  }
  const a = Buffer.from(expected);
  const b = Buffer.from(given);
  if (!crypto.timingSafeEqual(a, b)) return res.status(403).type('text/plain').send('bad csrf');
  next();
}
