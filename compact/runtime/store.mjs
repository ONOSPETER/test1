// Server-side storage for the vault: opaque encrypted blobs and one small 'head' pointer per vault.
// The server never sees keys or plaintext. MemStore is for tests; FsStore persists to a folder.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const ID = /^[0-9a-f]{64}$/;
const KID = /^[0-9a-f]{32}$/;
export const isId = (s) => ID.test(s);
export const isKid = (s) => KID.test(s);

export class MemStore {
  constructor({ maxBytes = 500 * 1024 * 1024 } = {}) {
    this.maxBytes = maxBytes; this.blobs = new Map(); this.heads = new Map(); this.snaps = new Map();
    this.writes = 0; this.bytes = 0;
  }
  persist() {}
  /** Replay protection: true the first time a key is seen within ttl seconds. */
  claim(key, ttlSec = 1800) {
    this.claims ??= new Map();
    const now = Date.now();
    if ((this.claims.get(key) ?? 0) > now) return false;
    this.claims.set(key, now + ttlSec * 1000);
    if (this.claims.size > 50_000) for (const [k, t] of this.claims) if (t <= now) this.claims.delete(k);
    return true;
  }
  putBlob(id, buf) {
    if (this.hasBlob(id)) return { id };
    if (this.bytes + buf.length > this.maxBytes) return { error: 'storage quota exceeded' };
    this.saveBlob(id, buf); this.bytes += buf.length;
    return { id };
  }
  hasBlob(id) { return this.blobs.has(id); }
  saveBlob(id, buf) { this.blobs.set(id, Buffer.from(buf)); }
  getBlob(id) { return this.blobs.get(id) ?? null; }
  getHead(kid) { return this.heads.get(kid) ?? null; }
  /** Optimistic concurrency: version must be exactly current + 1. */
  setHead(kid, n, id) {
    const cur = this.heads.get(kid);
    if ((cur?.n ?? 0) + 1 !== n) return { ok: false, n: cur?.n ?? 0 };
    if (!this.hasBlob(id)) return { ok: false, error: 'unknown blob', n: cur?.n ?? 0 };
    this.heads.set(kid, { n, id }); this.writes++; this.persist();
    return { ok: true };
  }
  leaves() { return [...this.heads].map(([kid, h]) => ({ kid, n: h.n, id: h.id })); }
  saveSnapshot(root, entries) {
    this.snaps.set(root, entries);
    while (this.snaps.size > 200) this.snaps.delete(this.snaps.keys().next().value); // bounded history
    this.persist(root);
  }
  getSnapshot(root) { return this.snaps.get(root) ?? null; }
  stats() { return { writes: this.writes, vaults: this.heads.size, blobs: this.blobCount(), bytes: this.bytes }; }
  blobCount() { return this.blobs.size; }
}

const writeAtomic = (file, data) => {
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(3).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, data); fs.renameSync(tmp, file);
};

export class FsStore extends MemStore {
  constructor(dir, opts) {
    super(opts);
    this.dir = dir; fs.mkdirSync(path.join(dir, 'blobs'), { recursive: true }); fs.mkdirSync(path.join(dir, 'snapshots'), { recursive: true });
    try {
      const j = JSON.parse(fs.readFileSync(path.join(dir, 'heads.json'), 'utf8'));
      this.heads = new Map(Object.entries(j.heads ?? {})); this.writes = j.writes ?? 0;
    } catch { /* first run, or unreadable: start empty (blobs are content addressed, nothing is lost) */ }
    for (const f of fs.readdirSync(path.join(dir, 'blobs'))) this.bytes += fs.statSync(path.join(dir, 'blobs', f)).size;
    for (const f of fs.readdirSync(path.join(dir, 'snapshots'))) {
      try { this.snaps.set(f.replace(/\.json$/, ''), JSON.parse(fs.readFileSync(path.join(dir, 'snapshots', f), 'utf8'))); } catch { /* skip */ }
    }
  }
  hasBlob(id) { return fs.existsSync(path.join(this.dir, 'blobs', id)); }
  saveBlob(id, buf) { writeAtomic(path.join(this.dir, 'blobs', id), buf); }
  getBlob(id) { try { return fs.readFileSync(path.join(this.dir, 'blobs', id)); } catch { return null; } }
  blobCount() { return fs.readdirSync(path.join(this.dir, 'blobs')).length; }
  persist(snapRoot) {
    writeAtomic(path.join(this.dir, 'heads.json'), JSON.stringify({ writes: this.writes, heads: Object.fromEntries(this.heads) }));
    if (snapRoot) writeAtomic(path.join(this.dir, 'snapshots', `${snapRoot}.json`), JSON.stringify(this.snaps.get(snapRoot)));
  }
}
