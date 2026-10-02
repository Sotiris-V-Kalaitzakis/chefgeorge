'use strict';
// Gallery admin API for chefgeorgecrete.com. Runs behind nginx at /api/ and edits
// data/gallery.json + images/uploads/ in the live webroot. No dependencies.
//
//   node server.js                         start the API
//   node server.js set-password <password> store a new admin password (signs out all sessions)

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');

const CONFIG_PATH = process.env.CG_CONFIG || path.join(__dirname, 'config.json');

const SESSION_COOKIE = 'cg_session';
const SESSION_DAYS = 30;
const MAX_UPLOAD = 15 * 1024 * 1024;
const MAX_JSON = 256 * 1024;
const MAX_ALT = 200;
const FAIL_LIMIT = 8;
const FAIL_WINDOW = 15 * 60 * 1000;
const UPLOADS_REL = 'images/uploads';
const GALLERY_REL = 'data/gallery.json';

function readConfig() {
  return fs.existsSync(CONFIG_PATH) ? JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) : {};
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function checkPassword(password, stored) {
  const [scheme, salt, hash] = String(stored || '').split('$');
  if (scheme !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64');
  const actual = crypto.scryptSync(password, Buffer.from(salt, 'base64'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

if (process.argv[2] === 'set-password') {
  const password = process.argv[3] || '';
  if (password.length < 10) {
    console.error('Usage: node server.js set-password <password of 10+ characters>');
    process.exit(1);
  }
  const cfg = readConfig();
  cfg.passwordHash = hashPassword(password);
  cfg.sessionSecret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  console.log(`Password saved to ${CONFIG_PATH}; existing sessions are signed out.`);
  process.exit(0);
}

const config = {
  port: 3107,
  webroot: '/var/www/chefgeorgecrete.com',
  secureCookie: true,
  devStatic: false,
  ...readConfig(),
};
if (!config.passwordHash || !config.sessionSecret) {
  console.error(`No password set. Run: node ${path.basename(__filename)} set-password <password>`);
  process.exit(1);
}

const galleryPath = path.join(config.webroot, GALLERY_REL);
const uploadsDir = path.join(config.webroot, UPLOADS_REL);

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(JSON.stringify(body));
}

// --- sessions -------------------------------------------------------------

function sign(value) {
  return crypto.createHmac('sha256', config.sessionSecret).update(value).digest('base64url');
}

function sessionCookie(value, maxAge) {
  const secure = config.secureCookie ? '; Secure' : '';
  return `${SESSION_COOKIE}=${value}; Path=/api; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

function hasSession(req) {
  const cookies = Object.fromEntries(
    (req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(([k, v]) => k && v)
  );
  const [expires, sig] = (cookies[SESSION_COOKIE] || '').split('.');
  if (!expires || !sig || Number(expires) < Date.now()) return false;
  const a = Buffer.from(sig);
  const b = Buffer.from(sign(expires));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Browsers always send Origin on cross-site writes; reject those on top of SameSite=Strict.
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

// --- login throttling -----------------------------------------------------

const failures = new Map();

function clientIp(req) {
  const remote = req.socket.remoteAddress || '';
  const fromProxy = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remote);
  return (fromProxy && req.headers['x-real-ip']) || remote;
}

function lockedOut(ip) {
  const f = failures.get(ip);
  if (f && Date.now() - f.since > FAIL_WINDOW) failures.delete(ip);
  return (failures.get(ip)?.count || 0) >= FAIL_LIMIT;
}

function recordFailure(ip) {
  const f = failures.get(ip);
  if (f) f.count++;
  else failures.set(ip, { count: 1, since: Date.now() });
}

// --- request bodies -------------------------------------------------------

function readBody(req, limit, tooBigMessage) {
  if (Number(req.headers['content-length']) > limit) {
    req.resume();
    return Promise.reject(httpError(413, tooBigMessage));
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size <= limit) chunks.push(chunk);
    });
    req.on('end', () => (size > limit ? reject(httpError(413, tooBigMessage)) : resolve(Buffer.concat(chunks))));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const raw = await readBody(req, MAX_JSON, 'Πολύ μεγάλο αίτημα.');
  try {
    const data = JSON.parse(raw.toString('utf8') || '{}');
    return data && typeof data === 'object' ? data : {};
  } catch {
    throw httpError(400, 'Μη έγκυρα δεδομένα.');
  }
}

function cleanAlt(value) {
  return String(value ?? '').replace(/[\s\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, MAX_ALT);
}

// --- gallery storage ------------------------------------------------------

async function readGallery() {
  try {
    const data = JSON.parse(await fsp.readFile(galleryPath, 'utf8'));
    return Array.isArray(data.images) ? data.images : [];
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
}

async function writeGallery(images) {
  const tmp = `${galleryPath}.tmp`;
  await fsp.mkdir(path.dirname(galleryPath), { recursive: true });
  await fsp.writeFile(tmp, JSON.stringify({ images }, null, 2) + '\n');
  await fsp.rename(tmp, galleryPath);
}

// Every change runs read → modify → write in turn, so parallel requests can't lose edits.
let queue = Promise.resolve();
function mutateGallery(change) {
  const run = queue.then(async () => {
    const next = await change(await readGallery());
    await writeGallery(next);
    return next;
  });
  queue = run.catch(() => {});
  return run;
}

// --- handlers -------------------------------------------------------------

async function login(req, res) {
  const ip = clientIp(req);
  if (lockedOut(ip)) {
    return send(res, 429, { error: 'Πολλές λάθος προσπάθειες. Δοκίμασε ξανά σε 15 λεπτά.' });
  }
  const { password } = await readJson(req);
  if (typeof password !== 'string' || !checkPassword(password, config.passwordHash)) {
    recordFailure(ip);
    return send(res, 401, { error: 'Λάθος κωδικός.' });
  }
  failures.delete(ip);
  send(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(makeSessionToken(), SESSION_DAYS * 86400) });
}

function makeSessionToken() {
  const expires = String(Date.now() + SESSION_DAYS * 86400 * 1000);
  return `${expires}.${sign(expires)}`;
}

// Reorder and caption edits only: the new list must hold exactly the photos already there.
async function updateGallery(req, res) {
  const body = await readJson(req);
  if (!Array.isArray(body.images)) throw httpError(400, 'Μη έγκυρα δεδομένα.');
  const stale = httpError(409, 'Η gallery άλλαξε στο μεταξύ. Ανανέωσε τη σελίδα.');
  const images = await mutateGallery(current => {
    const known = new Set(current.map(item => item.image));
    const seen = new Set();
    const next = body.images.map(item => {
      const image = item && item.image;
      if (!known.has(image) || seen.has(image)) throw stale;
      seen.add(image);
      return { image, alt: cleanAlt(item.alt) };
    });
    if (next.length !== current.length) throw stale;
    return next;
  });
  send(res, 200, { images });
}

// The browser resizes and re-encodes every photo to JPEG before sending it as the raw body.
async function uploadImage(req, res, url) {
  if (!/^image\/jpeg\b/i.test(req.headers['content-type'] || '')) {
    throw httpError(415, 'Μόνο εικόνες JPEG.');
  }
  const data = await readBody(req, MAX_UPLOAD, 'Η φωτογραφία είναι πολύ μεγάλη.');
  if (data.length < 4 || data[0] !== 0xff || data[1] !== 0xd8 || data[2] !== 0xff) {
    throw httpError(415, 'Το αρχείο δεν είναι έγκυρη εικόνα JPEG.');
  }
  const name = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}.jpg`;
  await fsp.mkdir(uploadsDir, { recursive: true });
  await fsp.writeFile(path.join(uploadsDir, name), data, { mode: 0o644 });
  const entry = { image: `${UPLOADS_REL}/${name}`, alt: cleanAlt(url.searchParams.get('alt')) };
  const images = await mutateGallery(current => [entry, ...current]);
  send(res, 201, { images });
}

// Deleted files move to a hidden .trash folder (nginx denies dot-paths), so a mistake can be undone by hand.
async function deleteImage(res, url) {
  const image = url.searchParams.get('image');
  const images = await mutateGallery(current => {
    if (!current.some(item => item.image === image)) throw httpError(404, 'Η φωτογραφία δεν βρέθηκε.');
    return current.filter(item => item.image !== image);
  });
  const name = image.slice(UPLOADS_REL.length + 1);
  if (image.startsWith(`${UPLOADS_REL}/`) && /^[\w-][\w.-]*$/.test(name)) {
    const trash = path.join(uploadsDir, '.trash');
    await fsp.mkdir(trash, { recursive: true });
    await fsp.rename(path.join(uploadsDir, name), path.join(trash, name)).catch(err => {
      if (err.code !== 'ENOENT') throw err;
    });
  }
  send(res, 200, { images });
}

// Local testing only; in production nginx serves the site and only /api/ reaches this server.
const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

async function serveStatic(pathname, res) {
  const root = path.resolve(config.webroot);
  let file = path.resolve(root, '.' + decodeURIComponent(pathname));
  if (!file.startsWith(root)) return send(res, 404, { error: 'Not found' });
  if (pathname.endsWith('/')) file = path.join(file, 'index.html');
  try {
    const data = await fsp.readFile(file);
    res.writeHead(200, { 'Content-Type': STATIC_TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  } catch {
    send(res, 404, { error: 'Not found' });
  }
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const route = `${req.method} ${url.pathname}`;

  if (!url.pathname.startsWith('/api/')) {
    return config.devStatic ? serveStatic(url.pathname, res) : send(res, 404, { error: 'Not found' });
  }
  if (req.method !== 'GET' && !sameOrigin(req)) return send(res, 403, { error: 'Forbidden' });

  if (route === 'POST /api/login') return login(req, res);
  if (route === 'POST /api/logout') return send(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });

  if (!hasSession(req)) return send(res, 401, { error: 'Απαιτείται σύνδεση.' });

  if (route === 'GET /api/gallery') return send(res, 200, { images: await readGallery() });
  if (route === 'PUT /api/gallery') return updateGallery(req, res);
  if (route === 'POST /api/images') return uploadImage(req, res, url);
  if (route === 'DELETE /api/images') return deleteImage(res, url);
  send(res, 404, { error: 'Not found' });
}

http
  .createServer((req, res) => {
    handle(req, res).catch(err => {
      if (!err.status) console.error(err);
      if (!res.headersSent) send(res, err.status || 500, { error: err.status ? err.message : 'Σφάλμα διακομιστή.' });
    });
  })
  .listen(config.port, '127.0.0.1', () => {
    console.log(`chefgeorge admin API on 127.0.0.1:${config.port}, webroot ${config.webroot}`);
  });
