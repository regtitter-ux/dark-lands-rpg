// Minimal SSR entry point. Chooses layout by req.uiMode and delegates to eta.

import { Eta } from 'eta';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { urlFor, csrfToken } from './session.js';
import { styleHref } from './assets.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const viewsDir = path.join(__dirname, '..', 'views');

const eta = new Eta({
  views: viewsDir,
  cache: process.env.NODE_ENV === 'production',
  autoEscape: true,
});

// Version string used to cache-bust /styles/*.css and /assets/*.
// Timestamp is fine because we serve those paths with `immutable` only when
// the query string is present, and the server restart picks up new content.
export const ASSET_VERSION = String(Date.now());

export function renderPage(req, res, template, data = {}) {
  const mode = req.uiMode === 'lite' ? 'lite' : 'rich';
  const ctx = {
    title: 'Сумрачные Земли',
    ...data,
    mode,
    path: req.originalUrl || req.url || '/',
    assetV: ASSET_VERSION,
    session: req.session || null,
    cookieless: !!req.cookieless,
    url: (p) => urlFor(req, p),
    csrf: () => csrfToken(req),
    asset: (name) => styleHref(name),
  };
  const body = eta.render(template, ctx);
  const html = eta.render(`_layout_${mode}`, { ...ctx, body });
  res.set('Cache-Control', 'no-store');
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
}
