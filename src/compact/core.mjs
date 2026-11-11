// Compact runtime core: shared by the runner (Node) and the viewer (browser).
// Only WebCrypto is used here. Post-quantum primitives are injected (see pq.mjs).
const te = new TextEncoder();
const td = new TextDecoder();

export const VERSION = 'compact-v1';
export const utf8 = { enc: (s) => te.encode(s), dec: (b) => td.decode(b) };

export const b64 = {
  enc(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  },
  dec(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

export const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest('SHA-256', u8));

/** Deterministic JSON: sorted keys, no whitespace. Used for manifest hashing/signing. */
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}
export const manifestHash = async (manifest) => sha256(utf8.enc(canonicalJson(manifest)));

// ---- classical building blocks (WebCrypto) -------------------------------------------------
export async function x25519Generate() {
  const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  return { privateKey: kp.privateKey, publicRaw: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}
export async function x25519Derive(privateKey, peerPublicRaw) {
  const peer = await crypto.subtle.importKey('raw', peerPublicRaw, { name: 'X25519' }, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256));
}
export async function hkdf(ikm, salt, info, bytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8.enc(info) }, key, bytes * 8));
}
export const aesKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
function nonce(seq) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, BigInt(seq));
  return n;
}
const aad = (sid, dir, seq) => utf8.enc(`${VERSION}|${sid}|${dir}|${seq}`);

// ---- hybrid handshake: X25519 + ML-KEM-768, server authenticated by ML-DSA-65 ---------------
const transcript = (clientX, kemCt, serverX, mHash, sid) =>
  sha256(concat(utf8.enc(VERSION), clientX, kemCt, serverX, mHash, utf8.enc(sid)));

async function deriveKeys(xSecret, kemSecret, th) {
  const okm = await hkdf(concat(xSecret, kemSecret), th, `${VERSION} session keys`, 64);
  return { c2s: await aesKey(okm.slice(0, 32)), s2c: await aesKey(okm.slice(32)), raw: okm };
}

export const keysFromRaw = async (raw) => ({ c2s: await aesKey(raw.slice(0, 32)), s2c: await aesKey(raw.slice(32)), raw });

// ---- stateless session tickets (for serverless hosts): the session keys travel with each request,
// sealed under a server-side ticket key, so any instance can serve any request ----
const TICKET_AAD = utf8.enc('compact-ticket-v1');
export async function sealTicket(ticketKey, { sid, exp, raw }) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: TICKET_AAD }, await aesKey(ticketKey), utf8.enc(JSON.stringify({ sid, exp, k: b64.enc(raw) })));
  return b64.enc(concat(iv, new Uint8Array(ct)));
}
export async function openTicket(ticketKey, ticket) {
  const bytes = b64.dec(ticket);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: TICKET_AAD }, await aesKey(ticketKey), bytes.slice(12));
  const t = JSON.parse(utf8.dec(new Uint8Array(pt)));
  if (!(t.exp > Date.now())) throw new Error('ticket expired');
  return { sid: t.sid, exp: t.exp, raw: b64.dec(t.k) };
}

/** Client step 1. `runnerKemPublic` comes from the signed manifest. */
export async function clientHello(pq, runnerKemPublic) {
  const x = await x25519Generate();
  const { cipherText, sharedSecret } = pq.kem.encapsulate(runnerKemPublic);
  return { hello: { x: b64.enc(x.publicRaw), ct: b64.enc(cipherText) }, state: { x, kemSecret: sharedSecret } };
}

/** Server step: derive keys, sign the transcript. Returns the reply and the session keys. */
export async function serverHello(pq, runnerKeys, hello, mHash, sid) {
  const clientX = b64.dec(hello.x);
  const ct = b64.dec(hello.ct);
  if (clientX.length !== 32) throw new Error('bad x25519 key');
  const kemSecret = pq.kem.decapsulate(ct, runnerKeys.kemSecret);
  const sx = await x25519Generate();
  const xSecret = await x25519Derive(sx.privateKey, clientX);
  const th = await transcript(clientX, ct, sx.publicRaw, mHash, sid);
  const sig = pq.dsa.sign(runnerKeys.dsaSecret, th);
  const keys = await deriveKeys(xSecret, kemSecret, th);
  return { reply: { sid, x: b64.enc(sx.publicRaw), sig: b64.enc(sig) }, keys, raw: keys.raw };
}

/** Client step 2: verify the server's ML-DSA signature, then derive the same keys. */
export async function clientFinish(pq, state, hello, reply, runnerDsaPublic, mHash) {
  const serverX = b64.dec(reply.x);
  const th = await transcript(b64.dec(hello.x), b64.dec(hello.ct), serverX, mHash, reply.sid);
  if (!pq.dsa.verify(runnerDsaPublic, th, b64.dec(reply.sig))) throw new Error('Server signature invalid: refusing to continue');
  const xSecret = await x25519Derive(state.x.privateKey, serverX);
  return deriveKeys(xSecret, state.kemSecret, th);
}

// ---- encrypted messages --------------------------------------------------------------------
export async function sealMessage(keys, dir, sid, seq, obj) {
  const key = dir === 'c2s' ? keys.c2s : keys.s2c;
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce(seq), additionalData: aad(sid, dir, seq) }, key, utf8.enc(JSON.stringify(obj)));
  return b64.enc(new Uint8Array(ct));
}
export async function openMessage(keys, dir, sid, seq, ctB64) {
  const key = dir === 'c2s' ? keys.c2s : keys.s2c;
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce(seq), additionalData: aad(sid, dir, seq) }, key, b64.dec(ctB64));
  return JSON.parse(utf8.dec(new Uint8Array(pt)));
}
