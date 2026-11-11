// Compact viewer core: runs in the portal (browser) and in Node tests. Verifies the critical side, opens a
// post-quantum-hardened channel to it, and exposes call()/http().
import * as core from './core.mjs';

export class CompactError extends Error {
  constructor(message, code = 'COMPACT_ERROR') { super(message); this.name = 'CompactError'; this.code = code; }
}

async function nearView(rpcUrls, account, method, argsBytes, fetchImpl) {
  let last;
  for (const url of rpcUrls) {
    try {
      const res = await fetchImpl(url, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function', finality: 'final', account_id: account, method_name: method, args_base64: core.b64.enc(argsBytes) } }),
      });
      const body = await res.json();
      if (body.error || body.result?.error) throw new Error(body.error?.message ?? String(body.result.error));
      return new Uint8Array(body.result.result);
    } catch (e) { last = e; }
  }
  throw last ?? new Error('no NEAR RPC endpoint configured');
}

export class CompactClient {
  constructor({ connect: c, manifest, pq, fetchImpl = (...a) => globalThis.fetch(...a) } = {}) {
    Object.assign(this, { connect: c, manifest, fetchImpl, seq: 0, session: null });
    this._pq = pq;
  }

  /** Same-origin ('auto') or absolute endpoint, plus the route prefix of this layout. */
  base() {
    const ep = this.connect.endpoint === 'auto' ? globalThis.location.origin : this.connect.endpoint;
    return ep + (this.connect.layout === 'vercel' ? '/api/compact' : '/.compact');
  }

  async #pq() {
    if (!this._pq) this._pq = (await import('./pq.mjs')).createPQ();
    return this._pq;
  }

  /** Check the on-chain registry record against the manifest this portal was built with. */
  async verifyRegistry(mHashHex) {
    const mode = this.connect.verify ?? 'warn';
    if (mode === 'off' || !this.connect.near?.registryAccount) return { checked: false };
    try {
      const key = await core.sha256(core.utf8.enc(this.connect.appId));
      const out = await nearView(this.connect.near.rpcUrls, this.connect.near.registryAccount, 'get', key, this.fetchImpl);
      const rec = JSON.parse(core.utf8.dec(out));
      if (rec.manifest !== mHashHex) throw new CompactError('On-chain manifest hash differs from this portal\'s manifest', 'REGISTRY_MISMATCH');
      return { checked: true, record: rec };
    } catch (e) {
      if (mode === 'strict' || e.code === 'REGISTRY_MISMATCH') throw e instanceof CompactError ? e : new CompactError(`Registry check failed: ${e.message}`, 'REGISTRY_UNREACHABLE');
      console.warn('[compact] registry check skipped:', e.message);
      return { checked: false };
    }
  }

  async open() {
    const pq = await this.#pq();
    const mHash = await core.manifestHash(this.manifest);
    const mHashHex = core.hex(mHash);
    await this.verifyRegistry(mHashHex);

    const res = await this.fetchImpl(`${this.base()}/bundle`);
    if (!res.ok) { await res.arrayBuffer().catch(() => {}); throw new CompactError(`Critical side unreachable (${res.status})`, 'UNREACHABLE'); }
    const bundle = await res.json();
    const served = core.hex(await core.manifestHash(bundle.manifest));
    if (served !== mHashHex) throw new CompactError('The server runs a different manifest than this portal expects', 'MANIFEST_MISMATCH');
    const dsaPub = core.b64.dec(this.manifest.runner.dsaPublic);
    if (!pq.dsa.verify(dsaPub, core.utf8.enc(core.canonicalJson(this.manifest)), core.b64.dec(bundle.sig))) {
      throw new CompactError('Manifest signature invalid', 'BAD_SIGNATURE');
    }

    const { hello, state } = await core.clientHello(pq, core.b64.dec(this.manifest.runner.kemPublic));
    const hr = await this.fetchImpl(`${this.base()}/hello`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(hello) });
    if (!hr.ok) { await hr.arrayBuffer().catch(() => {}); throw new CompactError(`Handshake rejected (${hr.status})`, 'HANDSHAKE'); }
    const reply = await hr.json();
    const keys = await core.clientFinish(pq, state, hello, reply, dsaPub, mHash);
    this.session = { sid: reply.sid, keys, ticket: reply.ticket };
    this.seq = 0;
  }

  async ready() { return (this._opening ??= this.open().catch((e) => { this._opening = null; throw e; })); }

  async #send(message, retried = false) {
    await this.ready();
    const { sid, keys } = this.session;
    const seq = ++this.seq;
    const res = await this.fetchImpl(`${this.base()}/msg`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-compact-sid': sid, ...(this.session.ticket ? { 'x-compact-ticket': this.session.ticket } : {}) },
      body: JSON.stringify({ seq, ct: await core.sealMessage(keys, 'c2s', sid, seq, message) }),
    });
    if (res.status === 401 && !retried) { await res.arrayBuffer().catch(() => {}); this._opening = null; this.session = null; return this.#send(message, true); } // server restarted or session expired
    if (!res.ok) { await res.arrayBuffer().catch(() => {}); throw new CompactError(`Request failed (${res.status})`, 'REQUEST'); }
    const body = await res.json();
    return core.openMessage(keys, 's2c', sid, body.seq, body.ct);
  }

  async call(module, fn, args) {
    const r = await this.#send({ t: 'rpc', module, fn, args });
    if (!r.ok) throw new CompactError(r.error?.message ?? 'remote error', 'REMOTE');
    return r.result;
  }

  async http({ method, path, headers, body }) {
    const r = await this.#send({ t: 'http', method, path, headers, body: body ? core.b64.enc(body) : undefined });
    if (!r.ok) throw new CompactError(r.error?.message ?? 'remote error', 'REMOTE');
    return { status: r.status, headers: r.headers, body: core.b64.dec(r.body) };
  }
}

