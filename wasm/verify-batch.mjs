#!/usr/bin/env node
/**
 * verify-batch.mjs — the 4-wide kernel must compute the same digests as
 * node:crypto, and must return the same nonce a sequential scan returns.
 * Batching changes how many nonces are in flight, never which one wins.
 *
 *   node wasm/verify-batch.mjs
 */
// nonce a sequential scan would.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const CH = '00112233445566778899aabbccddeeff0f1e2d3c4b5a69788796a5b4c3d2e1f0';
const ch = Buffer.from(CH, 'hex');
const le = ch[ch.length - 1] >= 0x80;

function digestOf(nonce) {
  const nb = Buffer.alloc(4);
  le ? nb.writeUInt32LE(nonce >>> 0) : nb.writeUInt32BE(nonce >>> 0);
  return createHash('sha256').update(ch).update(nb).digest();
}
const lz = (b) => { let n = 0; for (const x of b) { if (x === 0) { n += 8; continue; } n += Math.clz32(x) - 24; break; } return n; };

const { instance } = await WebAssembly.instantiate(readFileSync(new URL('./sha256_pow_batch.wasm', import.meta.url)),
  { anubis: { anubis_update_nonce: () => {} } });
const ex = instance.exports;
new Uint8Array(ex.memory.buffer).set(ch, ex.data_ptr());
ex.set_data_length(ch.length);

let bad = 0;
// difficulty 0 accepts the first candidate of each batch: walk batches and check
// that every returned digest equals node's for that nonce
for (const start of [0, 1, 7, 1234, 65535, 0xffffff00]) {
  const n = ex.anubis_work(0, start, 1);
  const got = Buffer.from(new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), 32));
  const want = digestOf(n);
  const ok = got.equals(want);
  if (!ok) bad++;
  console.log(`  start ${String(start).padStart(10)} -> nonce ${String(n >>> 0).padStart(10)}  ${ok ? 'digest matches node' : 'MISMATCH'}`);
}

// and the harder question: does it find the same nonce a sequential scan finds?
for (const difficulty of [8, 12, 16]) {
  const n = ex.anubis_work(difficulty, 0, 1);
  let seq = 0;
  while (lz(digestOf(seq)) < difficulty) seq++;
  const got = Buffer.from(new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), 32));
  const same = (n >>> 0) === seq && got.equals(digestOf(n)) && lz(got) >= difficulty;
  if (!same) bad++;
  console.log(`  difficulty ${String(difficulty).padStart(2)}: batch nonce ${n}, sequential ${seq}  ${same ? 'identical' : 'DIFFERENT'}`);
}
process.exitCode = bad === 0 ? 0 : 1;
console.log(bad === 0 ? '\nbatch kernel agrees with node and with a sequential scan' : `\n${bad} mismatch(es)`);
