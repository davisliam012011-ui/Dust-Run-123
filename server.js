'use strict';
/*
  Dust Run server: serves the game, runs the access-key paywall, and feeds the admin dashboard.
  Zero npm dependencies (Node 18+).

  Environment:
    ADMIN_KEY   required for /admin (16+ characters)
    PAYWALL     "on" to require an access key to open the game (default off)
    DATA_DIR    folder for db.json (a persistent disk on Render)
*/
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');

const PID = /^[A-Za-z0-9-]{8,64}$/;
const SESSION_GAP = 150e3;      // heartbeat gap that starts a new play session
const ONLINE_WINDOW = 50e3;     // heartbeat age that still counts as "online"
const MAX_PLAYERS = 100000;

function createApp(env) {
  const C = {
    port: +env.PORT || 3000,
    admin: env.ADMIN_KEY || '',
    paywall: /^(on|true|1)$/i.test(env.PAYWALL || ''),
    publicUrl: (env.PUBLIC_URL || env.RENDER_EXTERNAL_URL || '').replace(/\/+$/, ''),
    dataDir: path.resolve(env.DATA_DIR || path.join(__dirname, 'data')),
    pub: path.join(__dirname, 'public'),
    statsTtl: env.STATS_TTL_MS != null && env.STATS_TTL_MS !== '' ? +env.STATS_TTL_MS : 3000,
  };
  if (C.admin && C.admin.length < 16) throw new Error('ADMIN_KEY must be at least 16 characters');
  if (!C.admin) console.warn('[warn] ADMIN_KEY is not set: the admin dashboard is disabled');
  if (!env.DATA_DIR) console.warn('[warn] DATA_DIR is not set: data lives in ./data and is lost on redeploy unless that folder is on a persistent disk');

  /* ---------------- storage (one JSON file, written atomically) ---------------- */
  fs.mkdirSync(C.dataDir, { recursive: true });
  const file = path.join(C.dataDir, 'db.json');
  let db = { secret: '', keys: {}, players: {}, hours: {} };
  try { Object.assign(db, JSON.parse(fs.readFileSync(file, 'utf8'))); }
  catch (e) {
    if (e.code !== 'ENOENT') { console.error('[error] db.json unreadable, keeping a copy:', e.message); try { fs.copyFileSync(file, file + '.corrupt-' + Date.now()); } catch (x) {} }
  }
  if (!db.secret) db.secret = crypto.randomBytes(32).toString('hex');
  const hrs = new Map(); for (const k in db.hours) hrs.set(k, new Set(db.hours[k]));
  let nPlayers = Object.keys(db.players).length;
  const live = new Map();       // pid -> { t, state }  (memory only)
  let saveT = null;
  const hourKey = t => new Date(t).toISOString().slice(0, 13);
  function flush() {
    try {
      const cut = hourKey(Date.now() - 8 * 864e5); db.hours = {};
      for (const [k, s] of hrs) { if (k < cut) hrs.delete(k); else db.hours[k] = [...s]; }
      const tmp = file + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, file);
    } catch (e) { console.error('[error] db write failed:', e.message); }
  }
  function save() { if (saveT) return; saveT = setTimeout(() => { saveT = null; flush(); }, 1500); }

  /* ---------------- helpers ---------------- */
  const now = () => Date.now();
  const ipOf = req => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  const eq = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
  const buckets = new Map();
  const rl = {
    hit(k, win) { const t = now(); let b = buckets.get(k); if (!b || t > b.r) { b = { n: 0, r: t + win }; buckets.set(k, b); } b.n++; return b.n; },
    over(k, max) { const b = buckets.get(k); return !!b && now() < b.r && b.n >= max; },
  };
  const sweep = setInterval(() => { const t = now(); for (const [k, b] of buckets) if (t > b.r) buckets.delete(k); for (const [k, l] of live) if (t - l.t > 10 * 60e3) live.delete(k); }, 60e3); sweep.unref();
  // per-IP request budget: returns false once over
  const allow = (name, req, max, win = 60e3) => rl.hit(name + '|' + ipOf(req), win) <= max;

  const baseHeaders = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin' };
  function json(res, code, obj, extra) { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, baseHeaders, extra)); res.end(JSON.stringify(obj)); }
  const fail = (res, code, msg) => json(res, code, { error: msg });
  function readBody(req, max) {
    return new Promise((ok, bad) => {
      const a = []; let n = 0, dead = false;
      req.on('data', c => { if (dead) return; n += c.length; if (n > max) { dead = true; bad(Object.assign(new Error('too large'), { code: 413 })); return; } a.push(c); });
      req.on('end', () => { if (!dead) ok(Buffer.concat(a)); });
      req.on('error', e => { if (!dead) bad(e); });
    });
  }
  async function readJson(req) {
    const b = await readBody(req, 65536); if (!b.length) return {};
    try { const j = JSON.parse(b.toString('utf8')); return j && typeof j === 'object' && !Array.isArray(j) ? j : {}; }
    catch (e) { throw Object.assign(new Error('bad json'), { code: 400 }); }
  }
  const cleanName = s => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, 24) || 'OPERATOR';
  const cleanTag = (s, max = 12) => { s = String(s == null ? '' : s).slice(0, max); return /^[A-Za-z0-9_-]*$/.test(s) ? s : ''; };
  const int = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.round(+v) || 0));
  const isHttps = req => req.headers['x-forwarded-proto'] === 'https' || /^https:/.test(C.publicUrl);

  /* ---------------- paywall: signed cookie + device-limited keys ---------------- */
  const sign = s => crypto.createHmac('sha256', db.secret).update(s).digest('base64url');
  const mkCookie = (key, dev) => { const p = Buffer.from(JSON.stringify({ k: key, d: dev, e: now() + 180 * 864e5 })).toString('base64url'); return p + '.' + sign(p); };
  function cookieOf(req, name) {
    for (const part of String(req.headers.cookie || '').split(';')) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim(); }
    return '';
  }
  function hasAccess(req) {
    if (!C.paywall) return true;
    const v = cookieOf(req, 'dr_access'), i = v.indexOf('.'); if (i < 1) return false;
    const p = v.slice(0, i); if (!eq(sign(p), v.slice(i + 1))) return false;
    let o; try { o = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch (e) { return false; }
    const k = o && db.keys[o.k];
    return !!k && !k.revoked && o.e > now() && k.devices.includes(o.d);
  }
  function newKey() {
    const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', b = crypto.randomBytes(12); let s = '';
    for (let i = 0; i < 12; i++) s += A[b[i] % A.length] + (i % 4 === 3 && i < 11 ? '-' : '');
    return 'DR-' + s;
  }

  /* ---------------- player tracking (admin dashboard) ---------------- */
  function beat(b) {
    const id = b.id; if (typeof id !== 'string' || !PID.test(id)) return false;
    const t = now(); let p = db.players[id];
    if (b.bye) { live.delete(id); if (p) { p.last = t; save(); } return true; }
    if (!p) { if (nPlayers >= MAX_PLAYERS) return false; p = db.players[id] = { name: 'OPERATOR', first: t, last: t, sessions: 0, ms: 0, start: t }; nPlayers++; }
    const gap = t - (p.last || 0);
    if (!p.sessions || gap > SESSION_GAP) { p.sessions++; p.start = t; } else p.ms += Math.min(gap, 60e3);
    p.last = t; p.name = cleanName(b.name);
    live.set(id, { t, state: { m: b.m === 'play' ? 'play' : 'menu', map: cleanTag(b.map), p: cleanTag(b.p, 8).toUpperCase(), np: int(b.np, 0, 99), r: int(b.r, 0, 99), src: '' } });
    const k = hourKey(t); let s = hrs.get(k); if (!s) hrs.set(k, s = new Set()); s.add(id);
    save(); return true;
  }
  let statsCache = null;
  function stats() {
    const t = now(); if (statsCache && t - statsCache.at < C.statsTtl) return statsCache.v;
    const online = [];
    for (const [id, l] of live) { if (t - l.t > ONLINE_WINDOW) continue; const p = db.players[id]; if (p) online.push({ name: p.name, id: id.slice(0, 4), since: p.start, sessions: p.sessions, state: l.state }); }
    const uniq = h => { const s = new Set(); for (let i = 0; i < h; i++) { const set = hrs.get(hourKey(t - i * 3600e3)); if (set) for (const id of set) s.add(id); } return s.size; };
    const series = []; for (let i = 23; i >= 0; i--) { const k = hourKey(t - i * 3600e3); series.push({ h: k, n: hrs.has(k) ? hrs.get(k).size : 0 }); }
    let sess = 0, ms = 0; const all = Object.entries(db.players);
    for (const [, p] of all) { sess += p.sessions; ms += p.ms; }
    const recent = all.sort((a, b) => b[1].last - a[1].last).slice(0, 50).map(([id, p]) => ({ name: p.name, id: id.slice(0, 4), last: p.last, sessions: p.sessions, minutes: Math.round(p.ms / 6e3) / 10, first: p.first }));
    const v = {
      now: t, online: online.length, parties: new Set(online.map(o => o.state.p).filter(Boolean)).size,
      unique24h: uniq(24), unique7d: uniq(168), uniqueAll: all.length, avgMinutes: sess ? Math.round(ms / sess / 6e3) / 10 : 0,
      series, players: online, recent, paywall: C.paywall,
      keys: Object.values(db.keys).sort((a, b) => b.created - a.created).map(k => ({ key: k.key, note: k.note, uses: k.devices.length, maxUses: k.maxUses, revoked: !!k.revoked })),
    };
    statsCache = { at: t, v }; return v;
  }

  /* ---------------- static files (cached, gzipped) ---------------- */
  const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2' };
  const cache = new Map();
  function load(fp) {
    let c = cache.get(fp);
    if (!c) {
      const raw = fs.readFileSync(fp), ext = path.extname(fp).toLowerCase();
      c = { raw, type: MIME[ext] || 'application/octet-stream', etag: '"' + crypto.createHash('sha1').update(raw).digest('hex').slice(0, 20) + '"', gz: /^\.(html|js|css|json|svg|txt)$/.test(ext) ? zlib.gzipSync(raw, { level: 9 }) : null };
      cache.set(fp, c);
    }
    return c;
  }
  function sendFile(req, res, fp, extra) {
    let c; try { c = load(fp); } catch (e) { return fail(res, 404, 'not found'); }
    const h = Object.assign({ 'Content-Type': c.type, ETag: c.etag, 'Cache-Control': 'no-cache', Vary: 'Accept-Encoding' }, baseHeaders, extra);
    if (req.headers['if-none-match'] === c.etag) { res.writeHead(304, h); return res.end(); }
    const gz = c.gz && /\bgzip\b/.test(req.headers['accept-encoding'] || ''); if (gz) h['Content-Encoding'] = 'gzip';
    const body = gz ? c.gz : c.raw; h['Content-Length'] = body.length; res.writeHead(200, h); res.end(req.method === 'HEAD' ? undefined : body);
  }
  const ADMIN_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

  /* ---------------- routes ---------------- */
  async function api(req, res, url) {
    const m = req.method, p = url.pathname;

    if (p === '/api/hb' && m === 'POST') {
      if (!allow('hb', req, 90)) return fail(res, 429, 'slow down');
      return json(res, 200, { ok: beat(await readJson(req)) });
    }

    if (p === '/api/redeem' && m === 'POST') {
      const k0 = ipOf(req);
      if (rl.over('rf|' + k0, 10) || rl.over('rf|*', 100)) return fail(res, 429, 'Too many attempts. Try again later.');
      const b = await readJson(req), key = String(b.key || '').trim().toUpperCase(), dev = String(b.dev || ''), k = db.keys[key];
      if (!PID.test(dev)) return fail(res, 400, 'Bad device id.');
      if (!k || k.revoked) { rl.hit('rf|' + k0, 600e3); rl.hit('rf|*', 600e3); return fail(res, 403, 'That key is not valid.'); }
      if (!k.devices.includes(dev)) {
        if (k.maxUses > 0 && k.devices.length >= k.maxUses) return fail(res, 403, 'This key has reached its device limit.');
        if (k.devices.length < 5000) k.devices.push(dev); save();
      }
      return json(res, 200, { ok: true }, { 'Set-Cookie': 'dr_access=' + mkCookie(key, dev) + '; Path=/; Max-Age=' + 180 * 86400 + '; HttpOnly; SameSite=Lax' + (isHttps(req) ? '; Secure' : '') });
    }

    if (p.startsWith('/api/admin/')) {
      const k0 = ipOf(req);
      if (rl.over('af|' + k0, 10) || rl.over('af|*', 40)) return fail(res, 429, 'slow down');
      const given = req.headers['x-admin-key'];
      if (!(C.admin && given && eq(given, C.admin))) { if (given) { rl.hit('af|' + k0, 600e3); rl.hit('af|*', 600e3); } return fail(res, 401, 'auth'); }
      if (p === '/api/admin/stats' && m === 'GET') return json(res, 200, stats());
      if (p === '/api/admin/keys' && m === 'POST') {
        const b = await readJson(req), key = newKey();
        db.keys[key] = { key, note: String(b.note || '').replace(/[\u0000-\u001f\u007f<>]/g, '').slice(0, 40), maxUses: int(b.maxUses, 0, 1000), devices: [], revoked: false, created: now() };
        statsCache = null; save(); return json(res, 200, { ok: true, key });
      }
      if (p === '/api/admin/keys/revoke' && m === 'POST') {
        const k = db.keys[String((await readJson(req)).key || '')]; if (!k) return fail(res, 404, 'no such key');
        k.revoked = !k.revoked; statsCache = null; save(); return json(res, 200, { ok: true, revoked: k.revoked });
      }
    }
    return fail(res, 404, 'not found');
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x'), p = url.pathname;
      if (p === '/healthz') return json(res, 200, { ok: true });
      if (p.startsWith('/api/')) return await api(req, res, url);
      if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 405, 'method not allowed');
      if (isHttps(req)) baseHeaders['Strict-Transport-Security'] = 'max-age=15552000';
      if (p === '/' || p === '/index.html') {
        return hasAccess(req) ? sendFile(req, res, path.join(C.pub, 'index.html')) : sendFile(req, res, path.join(C.pub, 'gate.html'), { 'Cache-Control': 'no-store' });
      }
      if (p === '/admin' || p === '/admin.html') return sendFile(req, res, path.join(C.pub, 'admin.html'), { 'Content-Security-Policy': ADMIN_CSP, 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store' });
      // any other static asset in /public (never the game page itself, so the paywall can't be bypassed)
      const fp = path.resolve(C.pub, '.' + decodeURIComponent(p));
      const rel = path.relative(C.pub, fp);
      if (rel.startsWith('..') || path.isAbsolute(rel) || /(^|[\\/])\./.test(rel) || /^(index|gate|admin)\.html$/.test(rel)) return fail(res, 404, 'not found');
      return sendFile(req, res, fp);
    } catch (e) {
      if (e && (e.code === 413 || e.code === 400)) return fail(res, e.code, e.message);
      console.error('[error]', e && e.stack || e); if (!res.headersSent) fail(res, 500, 'server error'); else res.end();
    }
  });

  return {
    server, config: C, db, flush, stats,
    listen: (port, cb) => server.listen(port === undefined ? C.port : port, cb),
    close: cb => { clearInterval(sweep); if (saveT) { clearTimeout(saveT); saveT = null; } flush(); server.close(cb); },
  };
}

module.exports = { createApp };

if (require.main === module) {
  const app = createApp(process.env);
  app.listen(undefined, () => console.log('Dust Run listening on :' + app.config.port + ' · paywall ' + (app.config.paywall ? 'ON' : 'off') + ' · payments ' + (app.config.sk ? 'ON' : 'off') + ' · data ' + app.config.dataDir));
  const bye = () => { app.close(() => process.exit(0)); setTimeout(() => process.exit(0), 3000).unref(); };
  process.on('SIGTERM', bye); process.on('SIGINT', bye);
}
