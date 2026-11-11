// Compact Vault client: end-to-end encrypted storage that works on any host.
//
// Why this is post-quantum safe: the data path uses ONLY symmetric crypto (AES-256-GCM with a
// 256-bit key that never leaves the client). There is no public-key exchange that a quantum
// computer could break, so recorded traffic and stolen ciphertext stay unreadable.
// The host stores opaque padded blobs; it cannot read, search or alter them without detection.
// Rollback protection: a Merkle root of every vault head is anchored on NEAR occasionally;
// verify() checks the head the host serves against that anchor (reads are free view calls).
import * as core from './core.mjs';
import { leafHash, verifyProof } from './merkle.mjs';

export const BUCKETS = [4096, 16384, 65536, 262144, 1_000_000];
const te = core.utf8;

export class VaultError extends Error {
  constructor(message, code) { super(message); this.name = 'VaultError'; this.code = code; }
}

export function pad(data) {
  const size = BUCKETS.find((b) => b >= data.length + 4);
  if (!size) throw new VaultError('Record too large (limit about 1 MB)', 'TOO_LARGE');
  const out = new Uint8Array(size);
  new DataView(out.buffer).setUint32(0, data.length);
  out.set(data, 4);
  return out;
}
export function unpad(buf) {
  const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0);
  if (len > buf.length - 4) throw new VaultError('Corrupt record', 'CORRUPT');
  return buf.slice(4, 4 + len);
}

export const randomKey = () => crypto.getRandomValues(new Uint8Array(32));

/** A passphrase is only as strong as its guessability: the host holds ciphertext it can attack offline. Prefer randomKey(). */
export async function keyFromPassphrase(passphrase, salt, iterations = 600_000) {
  const base = await crypto.subtle.importKey('raw', te.enc(passphrase), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256));
}

const recordKey = async (root, nonce) => core.aesKey(await core.hkdf(root, nonce, 'compact-vault-v1 record', 32));
const aad = (kind) => te.enc(`compact-vault-v1|${kind}`);

export async function encryptRecord(root, kind, data) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(kind) }, await recordKey(root, nonce), pad(data));
  return core.concat(new Uint8Array([1]), nonce, new Uint8Array(ct));
}

export async function decryptRecord(root, kind, bytes) {
  if (bytes[0] !== 1) throw new VaultError('Unsupported record version', 'CORRUPT');
  const nonce = bytes.slice(1, 13);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(kind) }, await recordKey(root, nonce), bytes.slice(13));
    return unpad(new Uint8Array(pt));
  } catch (e) {
    if (e instanceof VaultError) throw e;
    throw new VaultError('Decryption failed: wrong key, or the data was tampered with', 'DECRYPT');
  }
}

const encodeValue = (v) => (v instanceof Uint8Array ? core.concat(new Uint8Array([0]), v) : core.concat(new Uint8Array([1]), te.enc(JSON.stringify(v))));
const decodeValue = (p) => (p[0] === 0 ? p.slice(1) : JSON.parse(te.dec(p.slice(1))));

async function nearView(rpcUrls, account, method, args, fetchImpl) {
  let last;
  for (const url of rpcUrls) {
    try {
      const res = await fetchImpl(url, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'query', params: { request_type: 'call_function', finality: 'final', account_id: account, method_name: method, args_base64: core.b64.enc(args) } }),
      });
      const body = await res.json();
      if (body.error || body.result?.error) return null; // contract panics when the key is absent
      return new Uint8Array(body.result.result);
    } catch (e) { last = e; }
  }
  throw new VaultError(`NEAR RPC unreachable: ${last?.message ?? 'no endpoint'}`, 'NEAR');
}

export class VaultClient {
  /** @param {{endpoint: string, appId: string, key: Uint8Array, fetchImpl?: Function, near?: {rpcUrls: string[], registryAccount: string}}} o */
  constructor({ endpoint, appId, key, fetchImpl = (...a) => globalThis.fetch(...a), near }) {
    if (!(key instanceof Uint8Array) || key.length !== 32) throw new VaultError('Vault key must be 32 bytes', 'KEY');
    Object.assign(this, { endpoint: endpoint.replace(/\/$/, ''), appId, key, fetchImpl, near });
  }

  async kid() { return (this._kid ??= core.hex(await core.hkdf(this.key, new Uint8Array(0), 'compact-vault-v1 kid', 16))); }
  #req(method, path, body, raw) {
    return this.fetchImpl(this.endpoint + path, { method, headers: body === undefined ? {} : { 'content-type': raw ? 'application/octet-stream' : 'application/json' }, body: body === undefined ? undefined : raw ? body : JSON.stringify(body) });
  }

  async head() {
    const r = await this.#req('GET', `/v1/head/${await this.kid()}`);
    if (r.status === 404) return null;
    if (!r.ok) throw new VaultError(`Could not read the vault head (${r.status})`, 'HTTP');
    return r.json();
  }
  async #getBlob(id) {
    const r = await this.#req('GET', `/v1/blob/${id}`);
    if (!r.ok) throw new VaultError(`Blob ${id.slice(0, 8)} is unavailable (${r.status})`, 'MISSING');
    const bytes = new Uint8Array(await r.arrayBuffer());
    if (core.hex(await core.sha256(bytes)) !== id) throw new VaultError('A blob does not match its hash: the host altered it', 'TAMPERED');
    return bytes;
  }
  async #putBlob(bytes) {
    const id = core.hex(await core.sha256(bytes));
    const r = await this.#req('PUT', '/v1/blob', bytes, true);
    if (!r.ok) throw new VaultError(`Upload failed (${r.status})`, 'HTTP');
    if ((await r.json()).id !== id) throw new VaultError('The host returned a different blob id', 'TAMPERED');
    return id;
  }
  async #load() {
    const h = await this.head();
    if (!h) return { n: 0, items: {} };
    const index = JSON.parse(te.dec(await decryptRecord(this.key, 'index', await this.#getBlob(h.id))));
    return { n: h.n, items: index.items };
  }
  async #save(cur, items) {
    const idxId = await this.#putBlob(await encryptRecord(this.key, 'index', te.enc(JSON.stringify({ v: 1, items }))));
    const r = await this.#req('PUT', `/v1/head/${await this.kid()}`, { n: cur.n + 1, id: idxId });
    if (r.status === 409) return false;
    if (!r.ok) throw new VaultError(`Could not update the vault head (${r.status})`, 'HTTP');
    return true;
  }

  async put(name, value) {
    for (let attempt = 0; attempt < 4; attempt++) { // retry if another device wrote first
      const cur = await this.#load();
      const id = await this.#putBlob(await encryptRecord(this.key, 'rec', encodeValue(value)));
      if (await this.#save(cur, { ...cur.items, [name]: { id } })) return { name, version: cur.n + 1 };
    }
    throw new VaultError('Too many concurrent writers; try again', 'CONFLICT');
  }
  async remove(name) {
    for (let attempt = 0; attempt < 4; attempt++) {
      const cur = await this.#load();
      const { [name]: gone, ...items } = cur.items;
      if (!gone) return false;
      if (await this.#save(cur, items)) return true;
    }
    throw new VaultError('Too many concurrent writers; try again', 'CONFLICT');
  }
  async get(name) {
    const { items } = await this.#load();
    return items[name] ? decodeValue(await decryptRecord(this.key, 'rec', await this.#getBlob(items[name].id))) : undefined;
  }
  async list() { return Object.keys((await this.#load()).items).sort(); }

  /**
   * Compare what the host serves with the Merkle root anchored on NEAR.
   * status: ok | rollback | unanchored | newer-than-anchor | proof-invalid | unreachable
   */
  async verify() {
    const kid = await this.kid();
    const head = await this.head();
    const out = { kid, version: head?.n ?? 0, status: 'ok', anchor: null };
    if (!this.near?.registryAccount) return { ...out, status: 'unanchored', note: 'No NEAR registry configured' };
    const key = await core.sha256(te.enc(`${this.appId}:root`));
    let raw;
    try { raw = await nearView(this.near.rpcUrls, this.near.registryAccount, 'get', key, this.fetchImpl); } catch (e) { return { ...out, status: 'unreachable', note: e.message }; }
    if (!raw) return { ...out, status: 'unanchored', note: 'Nothing has been anchored on-chain yet' };
    const anchor = JSON.parse(te.dec(raw));
    out.anchor = { root: anchor.root, count: anchor.count, ts: anchor.ts };
    const r = await this.#req('GET', `/v1/proof/${kid}?root=${anchor.root}`);
    if (r.status === 404) return { ...out, status: head ? 'newer-than-anchor' : 'ok', note: head ? 'Written after the last anchor (expected until the next commit)' : undefined };
    if (!r.ok) return { ...out, status: 'unreachable', note: `Proof request failed (${r.status})` };
    const p = await r.json();
    if (!(await verifyProof(await leafHash(kid, p.n, p.id), p.index, p.path, anchor.root))) return { ...out, status: 'proof-invalid', note: 'The host sent a proof that does not match the on-chain root' };
    out.anchoredVersion = p.n;
    if (!head || head.n < p.n) return { ...out, status: 'rollback', note: `The host serves version ${head?.n ?? 0}, but version ${p.n} was anchored on-chain` };
    return out;
  }
}
