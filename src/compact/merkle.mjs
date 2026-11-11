// Merkle tree over vault heads. Lets one small on-chain value commit to every user's latest head.
// Leaves are 32-byte hashes; the tree is built over leaves sorted by hash, so a given set always
// produces the same root. Domain separation: 0x00 prefix for leaves, 0x01 for inner nodes.
import { sha256, concat, utf8, hex } from './core.mjs';

export const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };

/** Leaf for one vault: commits to its pseudonymous id, head version and head blob id. */
export const leafHash = (kidHex, n, idHex) => sha256(concat(utf8.enc('compact-leaf-v1'), unhex(kidHex), u64(n), unhex(idHex)));

const node = (a, b) => sha256(concat(new Uint8Array([1]), a, b));

export async function buildTree(leaves) {
  if (!leaves.length) return { levels: [[]], root: new Uint8Array(32) };
  let level = await Promise.all(leaves.map((l) => sha256(concat(new Uint8Array([0]), l))));
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(await node(level[i], level[i + 1] ?? level[i]));
    levels.push(next);
    level = next;
  }
  return { levels, root: level[0] };
}

export function proofFor(levels, index) {
  const path = [];
  let i = index;
  for (let l = 0; l < levels.length - 1; l++) {
    const row = levels[l];
    path.push(hex(i % 2 === 0 ? (row[i + 1] ?? row[i]) : row[i - 1]));
    i = Math.floor(i / 2);
  }
  return path;
}

export async function verifyProof(leaf, index, path, rootHex) {
  let h = await sha256(concat(new Uint8Array([0]), leaf));
  let i = index;
  for (const sib of path) {
    const s = unhex(sib);
    h = i % 2 === 0 ? await node(h, s) : await node(s, h);
    i = Math.floor(i / 2);
  }
  return hex(h) === rootHex;
}

/** Sorted leaves + tree for a list of {kid, n, id}. Shared by every server flavour. */
export async function treeOfEntries(entries) {
  const withLeaf = await Promise.all(entries.map(async (e) => ({ ...e, leaf: await leafHash(e.kid, e.n, e.id) })));
  withLeaf.sort((a, b) => (hex(a.leaf) < hex(b.leaf) ? -1 : 1));
  const { levels, root } = await buildTree(withLeaf.map((e) => e.leaf));
  return { entries: withLeaf, levels, root: hex(root) };
}
