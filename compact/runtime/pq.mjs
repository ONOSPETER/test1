// Post-quantum primitives via @noble/post-quantum (ML-KEM-768, ML-DSA-65).
// The library changed its argument order for sign/verify between releases, so the adapter
// detects it with a self-test once and exposes one stable interface:
//   kem.keygen() / encapsulate(pub) / decapsulate(ct, secret)
//   dsa.keygen() / sign(secret, msg) / verify(pub, msg, sig)
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

function detectOrder() {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  const msg = new Uint8Array([1, 2, 3]);
  const attempts = {
    'msg-first': () => ml_dsa65.verify(ml_dsa65.sign(msg, secretKey), msg, publicKey),
    'key-first': () => ml_dsa65.verify(publicKey, msg, ml_dsa65.sign(secretKey, msg)),
  };
  for (const [name, run] of Object.entries(attempts)) {
    try { if (run() === true) return name; } catch { /* try the next order */ }
  }
  throw new Error('Unsupported @noble/post-quantum version: could not determine ML-DSA argument order');
}

let cached;
export function createPQ() {
  if (cached) return cached;
  const order = detectOrder();
  cached = {
    name: 'ml-kem-768 + ml-dsa-65',
    kem: {
      keygen: () => ml_kem768.keygen(),
      encapsulate: (pub) => ml_kem768.encapsulate(pub),
      decapsulate: (ct, secret) => ml_kem768.decapsulate(ct, secret),
    },
    dsa: {
      keygen: () => ml_dsa65.keygen(),
      sign: (secret, msg) => (order === 'msg-first' ? ml_dsa65.sign(msg, secret) : ml_dsa65.sign(secret, msg)),
      verify: (pub, msg, sig) => (order === 'msg-first' ? ml_dsa65.verify(sig, msg, pub) : ml_dsa65.verify(pub, msg, sig)),
    },
  };
  return cached;
}
