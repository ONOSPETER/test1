// Vault storage on a serverless host (Vercel): Upstash Redis over its REST API (plain fetch, no SDK).
// Works with the Upstash integration from the Vercel Marketplace. Blobs are stored base64-encoded.
// Same interface as MemStore, but every method is async.
export const SET_HEAD_LUA = `
local cur = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) and string.match(redis.call('HGET', KEYS[1], ARGV[1]), '^(%d+):') or '0')
if cur + 1 ~= tonumber(ARGV[2]) then return {0, cur} end
if redis.call('EXISTS', KEYS[2]) == 0 then return {2, cur} end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2] .. ':' .. ARGV[3])
redis.call('INCR', KEYS[3])
return {1, cur}`.trim();

export class UpstashStore {
  constructor({ url, token, fetchImpl = (...a) => globalThis.fetch(...a), prefix = 'compact:' }) {
    Object.assign(this, { url: url.replace(/\/$/, ''), token, fetchImpl, prefix });
    this.name = 'upstash';
  }
  static fromEnv(env = process.env, opts = {}) {
    const url = env.UPSTASH_REDIS_REST_URL ?? env.KV_REST_API_URL;
    const token = env.UPSTASH_REDIS_REST_TOKEN ?? env.KV_REST_API_TOKEN;
    return url && token ? new UpstashStore({ url, token, ...opts }) : null;
  }
  async #post(path, body) {
    const res = await this.fetchImpl(this.url + path, { method: 'POST', headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`Redis REST error ${res.status}: ${j.error ?? 'unknown'}`);
    return j;
  }
  async cmd(...args) { const j = await this.#post('', args); if (j.error) throw new Error(`Redis error: ${j.error}`); return j.result; }
  async pipeline(cmds) { const r = await this.#post('/pipeline', cmds); return r.map((x) => { if (x.error) throw new Error(`Redis error: ${x.error}`); return x.result; }); }
  k(s) { return this.prefix + s; }

  async claim(key, ttlSec = 1800) { return (await this.cmd('SET', this.k(`claim:${key}`), '1', 'NX', 'EX', ttlSec)) === 'OK'; }
  async putBlob(id, buf) {
    const set = await this.cmd('SET', this.k(`b:${id}`), Buffer.from(buf).toString('base64'), 'NX');
    if (set === 'OK') await this.cmd('INCRBY', this.k('bytes'), buf.length);
    return { id };
  }
  async getBlob(id) { const v = await this.cmd('GET', this.k(`b:${id}`)); return v ? Buffer.from(v, 'base64') : null; }
  async getHead(kid) {
    const v = await this.cmd('HGET', this.k('heads'), kid);
    if (!v) return null;
    const [n, id] = v.split(':');
    return { n: Number(n), id };
  }
  async setHead(kid, n, id) {
    const [code, cur] = await this.cmd('EVAL', SET_HEAD_LUA, 3, this.k('heads'), this.k(`b:${id}`), this.k('writes'), kid, n, id);
    if (code === 1) return { ok: true };
    return code === 2 ? { ok: false, error: 'unknown blob', n: cur } : { ok: false, n: cur };
  }
  async leaves() {
    const flat = (await this.cmd('HGETALL', this.k('heads'))) ?? [];
    const out = [];
    for (let i = 0; i < flat.length; i += 2) { const [n, id] = flat[i + 1].split(':'); out.push({ kid: flat[i], n: Number(n), id }); }
    return out;
  }
  async saveSnapshot(root, entries) { await this.cmd('SET', this.k(`snap:${root}`), JSON.stringify(entries), 'EX', 60 * 60 * 24 * 180); }
  async getSnapshot(root) { const v = await this.cmd('GET', this.k(`snap:${root}`)); return v ? JSON.parse(v) : null; }
  async stats() {
    const [w, b, v] = await this.pipeline([['GET', this.k('writes')], ['GET', this.k('bytes')], ['HLEN', this.k('heads')]]);
    return { writes: Number(w ?? 0), bytes: Number(b ?? 0), vaults: Number(v ?? 0) };
  }
}
