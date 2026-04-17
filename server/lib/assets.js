import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, '..', 'public');
const stylesDir = path.join(publicDir, 'styles');

const hashes = new Map();
let spaHtml = null;

function shortHash(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex').slice(0, 8);
}

export function initAssets() {
  hashes.clear();
  if (fs.existsSync(stylesDir)) {
    for (const f of fs.readdirSync(stylesDir)) {
      if (!f.endsWith('.css')) continue;
      const base = f.slice(0, -4);
      if (/\.[0-9a-f]{8}$/i.test(base)) continue;
      const buf = fs.readFileSync(path.join(stylesDir, f));
      hashes.set(base, shortHash(buf));
    }
  }
  const indexPath = path.join(publicDir, 'index.html');
  if (fs.existsSync(indexPath)) {
    const src = fs.readFileSync(indexPath, 'utf8');
    spaHtml = src.replace(
      /href="\/styles\/rich\.css"/,
      `href="${styleHref('rich')}"`
    );
  }
}

export function styleHref(name) {
  const h = hashes.get(name);
  return h ? `/styles/${name}.${h}.css` : `/styles/${name}.css`;
}

export function getSpaHtml() {
  return spaHtml;
}

export function hashedStylesMiddleware(req, res, next) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  const m = req.path.match(/^\/styles\/([A-Za-z0-9_-]+)\.([0-9a-f]{8})\.css$/);
  if (!m) return next();
  const name = m[1];
  const hash = m[2];
  const known = hashes.get(name);
  if (!known || known !== hash) return next();
  const fp = path.join(stylesDir, name + '.css');
  if (!fs.existsSync(fp)) return next();
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.set('Content-Type', 'text/css; charset=utf-8');
  res.sendFile(fp);
}
