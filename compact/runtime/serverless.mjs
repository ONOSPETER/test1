// Compact on Vercel (or any serverless Node host): ONE function serving the post-quantum channel,
// the encrypted vault and your critical code. Nothing is kept in memory between requests that
// another instance would need:
//   - sessions travel as sealed tickets (see core.sealTicket), so any instance can answer;
//   - vault blobs, heads and replay claims live in Redis (Upstash REST), not on a disk.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as core from './core.mjs';
import { isId, isKid } from './store.mjs';
import { proofFor, treeOfEntries } from './merkle.mjs';
import { UpstashStore } from './kv.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MAX_BODY = 2 * 1024 * 1024;
const MAX_BLOB = 262_144 + 64; // Redis REST request limits: records up to about 256 KB on this layout
const TICKET_TTL_MS = 30 * 60_000;
const CALL_TIMEOUT_MS = 30_000;
const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length']);

class ConfigError extends Error {}
const httpError = (status, message) => Object.assign(new Error(message), { status });
const withTimeout = (p, ms, what) => {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out`)), ms); })]).finally(() => clearTimeout(t));
};

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(obj));
}

/** Vercel pre-parses request bodies into req.body; elsewhere we read the stream. Handle both. */
async function bodyOf(req, limit) {
  let buf;
  if (req.body !== undefined && req.body !== null) buf = Buffer.isBuffer(req.body) ? req.body : Buffer.from(typeof req.body === 'string' ? req.body : JSON.stringify(req.body));
  else buf = await new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > limit) { reject(httpError(413, 'body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
  if (buf.length > limit) throw httpError(413, 'body too large');
  return buf;
}
const jsonBody = async (req) => { try { return JSON.parse((await bodyOf(req, MAX_BODY)).toString('utf8') || '{}'); } catch (e) { throw e.status ? e : httpError(400, 'invalid JSON'); } };

async function waitForPort(port, timeoutMs = 25_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const ok = await new Promise((resolve) => { const s = net.connect(port, '127.0.0.1'); s.once('connect', () => { s.destroy(); resolve(true); }); s.once('error', () => resolve(false)); });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`critical app did not open port ${port} in time`);
}

function checkIntegrity(manifest, dir) {
  const bad = [];
  for (const f of manifest.critical?.files ?? []) {
    try { if (crypto.createHash('sha256').update(fs.readFileSync(path.join(dir, f.path))).digest('hex') !== f.sha256) bad.push(f.path); } catch { bad.push(f.path); }
  }
  return { ok: bad.length === 0, changed: bad.slice(0, 10) };
}

/**
 * @param {{basePath?: string, manifest?: object, manifestSig?: string, keys?: object, pq?: object, store?: object,
 *          criticalDir?: string, ticketKey?: Uint8Array}} [opts]  everything defaults to files + environment variables
 */
export function createServerlessHandler(opts = {}) {
  const basePath = opts.basePath ?? '/api/compact';
  let ready;

  async function init() {
    const manifest = opts.manifest ?? JSON.parse(fs.readFileSync(path.join(HERE, '..', 'manifest.json'), 'utf8'));
    const manifestSig = opts.manifestSig ?? fs.readFileSync(path.join(HERE, '..', 'manifest.sig'), 'utf8').trim();
    let keys = opts.keys;
    if (!keys) {
      if (!process.env.COMPACT_KEYS_B64) throw new ConfigError('COMPACT_KEYS_B64 is not set (run `compact keys --b64` and add it as a Vercel environment variable)');
      const k = JSON.parse(Buffer.from(process.env.COMPACT_KEYS_B64, 'base64').toString('utf8'));
      if (k.kem.public !== manifest.runner.kemPublic || k.dsa.public !== manifest.runner.dsaPublic) throw new ConfigError('COMPACT_KEYS_B64 does not match the manifest');
      keys = { kemSecret: core.b64.dec(k.kem.secret), dsaSecret: core.b64.dec(k.dsa.secret) };
    }
    const criticalDir = opts.criticalDir ?? path.join(HERE, '..', 'critical');
    const ticketKey = opts.ticketKey ?? (process.env.COMPACT_TICKET_KEY ? core.b64.dec(process.env.COMPACT_TICKET_KEY)
      : await core.sha256(core.concat(keys.dsaSecret, keys.kemSecret, core.utf8.enc('compact-ticket-key-v1'))));
    return {
      manifest, manifestSig, keys, criticalDir, ticketKey,
      pq: opts.pq ?? (await import('./pq.mjs')).createPQ(),
      store: opts.store ?? UpstashStore.fromEnv(),
      mHash: await core.manifestHash(manifest),
      appPort: manifest.critical.http?.port ?? 0,
      integrity: checkIntegrity(manifest, criticalDir), modules: new Map(), treeCache: { writes: -1 },
    };
  }

  // ---- critical code ----
  function ensureApp(c) {
    return (c.appReady ??= (async () => {
      process.env.PORT = String(c.appPort);
      await import(pathToFileURL(path.join(c.criticalDir, c.manifest.critical.entry)).href); // the app starts listening on localhost
      await waitForPort(c.appPort);
    })().catch((e) => { c.appReady = null; throw e; }));
  }
  async function dispatch(c, msg) {
    if (msg.t === 'rpc') {
      const allow = c.manifest.critical.rpc?.allow ?? {};
      if (typeof msg.module !== 'string' || typeof msg.fn !== 'string' || !Array.isArray(msg.args)) throw new Error('bad rpc message');
      if (!Object.hasOwn(allow, msg.module) || !allow[msg.module].includes(msg.fn)) throw new Error('function not exposed');
      if (!c.modules.has(msg.module)) c.modules.set(msg.module, import(pathToFileURL(path.join(c.criticalDir, msg.module)).href));
      const m = await c.modules.get(msg.module);
      const fn = msg.fn === 'default' ? m.default : (m[msg.fn] ?? m.default?.[msg.fn]);
      if (typeof fn !== 'function') throw new Error('export is not a function');
      const result = await withTimeout(Promise.resolve(fn(...msg.args)), CALL_TIMEOUT_MS, 'call');
      JSON.stringify(result);
      return { ok: true, result: result === undefined ? null : result };
    }
    if (msg.t === 'http') {
      const prefixes = c.manifest.critical.http?.prefixes ?? [];
      const p = String(msg.path ?? '');
      if (!p.startsWith('/') || p.startsWith('//') || p.includes('..') || /[\r\n]/.test(p)) throw new Error('bad path');
      if (!prefixes.some((x) => p === x || p.startsWith(`${x}/`) || p.startsWith(`${x}?`))) throw new Error('path not exposed');
      if (!/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(msg.method)) throw new Error('bad method');
      await ensureApp(c);
      const headers = {};
      for (const [k, v] of Object.entries(msg.headers ?? {})) if (!HOP.has(k.toLowerCase())) headers[k] = String(v);
      const body = msg.body && !['GET', 'HEAD'].includes(msg.method) ? Buffer.from(msg.body, 'base64') : undefined;
      const r = await fetch(`http://127.0.0.1:${c.appPort}${p}`, { method: msg.method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(CALL_TIMEOUT_MS) });
      const rh = {};
      r.headers.forEach((v, k) => { if (!HOP.has(k) && k !== 'set-cookie') rh[k] = v; });
      return { ok: true, status: r.status, headers: rh, body: Buffer.from(await r.arrayBuffer()).toString('base64') };
    }
    throw new Error('unknown message type');
  }

  // ---- channel ----
  async function onHello(c, req, res) {
    const hello = await jsonBody(req);
    const sid = crypto.randomBytes(16).toString('hex');
    const { reply, raw } = await core.serverHello(c.pq, c.keys, hello, c.mHash, sid);
    send(res, 200, { ...reply, ticket: await core.sealTicket(c.ticketKey, { sid, exp: Date.now() + TICKET_TTL_MS, raw }) });
  }
  async function onMsg(c, req, res) {
    if (!c.store) throw new ConfigError('Storage is not configured (set the Upstash Redis variables): replay protection needs it');
    let t;
    try { t = await core.openTicket(c.ticketKey, String(req.headers['x-compact-ticket'] ?? '')); } catch { return send(res, 401, { error: 'unknown session' }); }
    const body = await jsonBody(req);
    const seq = Number(body.seq);
    if (!Number.isSafeInteger(seq) || seq < 1) return send(res, 409, { error: 'replay or bad sequence' });
    if (!(await c.store.claim(`${t.sid}:${seq}`, TICKET_TTL_MS / 1000))) return send(res, 409, { error: 'replay or bad sequence' });
    const keys = await core.keysFromRaw(t.raw);
    let msg;
    try { msg = await core.openMessage(keys, 'c2s', t.sid, seq, body.ct); } catch { return send(res, 400, { error: 'decryption failed' }); }
    let reply;
    try { reply = await dispatch(c, msg); } catch (e) { reply = { ok: false, error: { message: String(e?.message ?? e).slice(0, 300) } }; }
    send(res, 200, { seq, ct: await core.sealMessage(keys, 's2c', t.sid, seq, reply) });
  }

  // ---- vault ----
  async function currentTree(c) {
    const { writes } = await c.store.stats();
    if (c.treeCache.writes !== writes) c.treeCache = { writes, ...(await treeOfEntries(await c.store.leaves())) };
    return c.treeCache;
  }
  async function onVault(c, req, res, p, url) {
    if (!c.store) throw new ConfigError('Storage is not configured (set the Upstash Redis variables)');
    const [, kind, arg = ''] = p.split('/').filter(Boolean);
    if (kind === 'blob' && req.method === 'PUT' && !arg) {
      const body = await bodyOf(req, MAX_BLOB);
      if (body.length < 30) return send(res, 400, { error: 'blob too small' });
      const id = crypto.createHash('sha256').update(body).digest('hex');
      const r = await c.store.putBlob(id, body);
      return r.error ? send(res, 507, { error: r.error }) : send(res, 200, { id, size: body.length });
    }
    if (kind === 'blob' && req.method === 'GET' && isId(arg)) {
      const b = await c.store.getBlob(arg);
      if (!b) return send(res, 404, { error: 'not found' });
      res.statusCode = 200; res.setHeader('content-type', 'application/octet-stream'); res.setHeader('cache-control', 'public, max-age=31536000, immutable');
      return res.end(b);
    }
    if (kind === 'head' && isKid(arg)) {
      if (req.method === 'GET') { const h = await c.store.getHead(arg); return h ? send(res, 200, h) : send(res, 404, { error: 'no head' }); }
      if (req.method === 'PUT') {
        const b = await jsonBody(req);
        if (!Number.isSafeInteger(b.n) || b.n < 1 || !isId(String(b.id))) return send(res, 400, { error: 'bad head' });
        const r = await c.store.setHead(arg, b.n, b.id);
        return r.ok ? send(res, 200, { ok: true }) : send(res, r.error ? 400 : 409, { error: r.error ?? 'conflict', n: r.n });
      }
    }
    if (kind === 'root' && req.method === 'GET') {
      const t = await currentTree(c);
      return send(res, 200, { root: t.root, count: t.entries.length, writes: t.writes, ts: new Date().toISOString() });
    }
    if (kind === 'stats' && req.method === 'GET') return send(res, 200, await c.store.stats());
    if (kind === 'snapshot' && req.method === 'POST') {
      const b = await jsonBody(req);
      const t = await currentTree(c);
      if (b.root !== t.root) return send(res, 409, { error: 'root changed', root: t.root });
      await c.store.saveSnapshot(t.root, t.entries.map(({ kid, n, id }) => ({ kid, n, id })));
      return send(res, 200, { ok: true, root: t.root });
    }
    if (kind === 'proof' && req.method === 'GET' && isKid(arg)) {
      const wanted = url.searchParams.get('root');
      let t = await currentTree(c);
      if (wanted && wanted !== t.root) {
        const snap = await c.store.getSnapshot(wanted);
        if (!snap) return send(res, 404, { error: 'unknown root' });
        t = await treeOfEntries(snap);
      }
      const i = t.entries.findIndex((e) => e.kid === arg);
      if (i < 0) return send(res, 404, { error: 'no leaf' });
      return send(res, 200, { n: t.entries[i].n, id: t.entries[i].id, index: i, path: proofFor(t.levels, i), root: t.root, count: t.entries.length });
    }
    return send(res, 404, { error: 'not found' });
  }

  return async function handler(req, res) {
    try {
      const c = await (ready ??= init().catch((e) => { ready = null; throw e; }));
      const url = new URL(req.url, 'http://x');
      if (!url.pathname.startsWith(basePath)) return send(res, 404, { error: 'not found' });
      const p = url.pathname.slice(basePath.length) || '/';
      const allowed = (process.env.COMPACT_ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
      const origin = req.headers.origin;
      if (origin && allowed.length && (allowed.includes('*') || allowed.includes(origin))) {
        res.setHeader('access-control-allow-origin', allowed.includes('*') ? '*' : origin);
        res.setHeader('vary', 'origin');
        res.setHeader('access-control-allow-headers', 'content-type, x-compact-sid, x-compact-ticket');
        res.setHeader('access-control-allow-methods', 'GET, POST, PUT, OPTIONS');
      }
      if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
      if (req.method === 'GET' && p === '/health') return send(res, 200, { ok: true, mode: c.manifest.mode, layout: 'vercel', store: c.store?.name ?? (c.store ? 'custom' : 'none'), integrity: c.integrity });
      if (req.method === 'GET' && p === '/bundle') return send(res, 200, { manifest: c.manifest, sig: c.manifestSig });
      if (req.method === 'POST' && p === '/hello') return await onHello(c, req, res);
      if (req.method === 'POST' && p === '/msg') return await onMsg(c, req, res);
      if (p.startsWith('/v1/')) return await onVault(c, req, res, p, url);
      send(res, 404, { error: 'not found' });
    } catch (e) {
      if (res.headersSent) return;
      if (e instanceof ConfigError) return send(res, 503, { error: e.message });
      if (e.status) return send(res, e.status, { error: e.message });
      console.error('[compact] request error:', e?.stack ?? e);
      send(res, 500, { error: 'internal error' });
    }
  };
}
