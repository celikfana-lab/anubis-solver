#!/usr/bin/env node
/**
 * verify.mjs — do the compiled WAT and the official Anubis module agree?
 *
 * Both derive the HashX program from the same 32-byte challenge and scan the same
 * nonce sequence, so at a given difficulty they must find the *same* nonce and the
 * *same* digest. This is the check the demo page performs in the browser, run
 * headless so it can be part of CI.
 *
 *   node wasm/verify.mjs
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CHALLENGE_HEX = '6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d';
const EXPECTED = '046eec4a54205736|92fa2440753b292e|93f4121c1d4c2b5c|e39da32f2048533f';
const DIFFICULTY = 16;

const words = (bytes) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return [0, 1, 2, 3].map((i) => view.getBigUint64(8 * i, true).toString(16).padStart(16, '0')).join('|');
};

let failures = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`);
  if (!ok) failures++;
};

const challenge = Buffer.from(CHALLENGE_HEX, 'hex');
const jitBytes = readFileSync(join(HERE, 'hashx_jit.wasm'));
const { instance: jit } = await WebAssembly.instantiate(jitBytes, {});

// --- our module, first ---
const jitLz = Number(jit.exports.hash(0n));
const jitDigest0 = new Uint8Array(jit.exports.memory.buffer, 0, 32).slice();
check('compiled WAT: digest(nonce 0) matches the C engine', words(jitDigest0) === EXPECTED, words(jitDigest0));
check('compiled WAT: hash() returns the digest leading zero bits', jitLz === 2, `${jitLz} bits`);

const t0 = performance.now();
const jitNonce = Number(jit.exports.solve(0n, BigInt(DIFFICULTY), BigInt(1 << 24)));
const jitSeconds = (performance.now() - t0) / 1000;
const jitDigest = new Uint8Array(jit.exports.memory.buffer, 0, 32).slice();
check(`compiled WAT: solved difficulty ${DIFFICULTY}`, jitNonce >= 0, `nonce ${jitNonce}`);

// --- the official module, on the identical challenge ---
let sawOfficial = false;
for (const [label, file] of [['baseline', 'official/hashx-baseline.wasm'], ['simd128', 'official/hashx-simd128.wasm']]) {
  const path = join(HERE, 'demo', file);
  if (!existsSync(path)) {
    console.log(`  skip official ${label}: ${path} not present`);
    continue;
  }
  sawOfficial = true;
  const { instance } = await WebAssembly.instantiate(readFileSync(path), {
    anubis: { anubis_update_nonce: () => {} },
  });
  const ex = instance.exports;
  // the view is re-created after the call: anubis_work can grow linear memory,
  // which detaches every TypedArray view taken before it
  new Uint8Array(ex.memory.buffer).set(challenge, ex.data_ptr());
  ex.set_data_length(challenge.length);

  const t1 = performance.now();
  const nonce = ex.anubis_work(DIFFICULTY, 0, 1);
  const seconds = (performance.now() - t1) / 1000;
  const mem = new Uint8Array(ex.memory.buffer);
  const digest = mem.slice(ex.result_hash_ptr(), ex.result_hash_ptr() + ex.result_hash_size());

  check(`official ${label}: same nonce as ours`, nonce === jitNonce, `theirs ${nonce}, ours ${jitNonce}`);
  check(`official ${label}: same digest as ours`, words(digest) === words(jitDigest), words(digest));
  console.log(`       ours ${(jitSeconds * 1e3).toFixed(0)} ms, theirs ${(seconds * 1e3).toFixed(0)} ms` +
              `  -> ${(seconds / jitSeconds).toFixed(2)}x slower`);
}
if (!sawOfficial) console.log('  no official modules: put them in wasm/demo/official/ (see its README)');

console.log(`\n${failures === 0 ? 'all checks passed' : failures + ' check(s) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
