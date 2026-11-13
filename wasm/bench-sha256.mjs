#!/usr/bin/env node
/**
 * bench-sha256.mjs — fixed-work SHA-256 rate, the measurement that actually ranks
 * the kernels. A single solve at the server's difficulty is a few thousand hashes
 * and lands inside the wasm tier-up window, so it measures compilation, not hashing.
 *
 *   node bench-sha256.mjs [--difficulty 22] [--rounds 3]
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const OFFICIAL = process.env.ANUBIS_WASM_DIR ??
  '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm';

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? Number(argv[i + 1]) : d; };
const DIFF = flag('difficulty', 22);
const ROUNDS = flag('rounds', 3);

// fixed challenge, last byte < 0x80 so every module takes the big-endian nonce path
const CH = Buffer.from('9f2c1b4a7e5d3c0b8a1f6e2d4c7b0a9f5e3d1c8b7a6f4e2d1c0b9a8f7e6d5c4b', 'hex');

const CASES = [
  [`${OFFICIAL}/simd128/sha256.wasm`, 'official simd128'],
  [`${OFFICIAL}/baseline/sha256.wasm`, 'official baseline'],
  [`${HERE}sha256_pow.wasm`, 'ours (scalar schedule)'],
];

async function rate(path) {
  const { instance } = await WebAssembly.instantiate(readFileSync(path),
    { anubis: { anubis_update_nonce: () => {} } });
  const ex = instance.exports;
  new Uint8Array(ex.memory.buffer).set(CH, ex.data_ptr());
  ex.set_data_length(CH.length);
  ex.anubis_work(8, 0, 1);                              // warm the tier-up compiler
  let best = Infinity;
  let nonce = 0;
  for (let r = 0; r < ROUNDS; r++) {
    const t0 = process.hrtime.bigint();
    nonce = ex.anubis_work(DIFF, 0, 1);
    best = Math.min(best, Number(process.hrtime.bigint() - t0));
  }
  const n = nonce + 1;
  return { rate: (n / best) * 1e9, us: best / n / 1000, bytes: readFileSync(path).length };
}

console.log(`SHA-256 proof of work, difficulty ${DIFF}, warm, best of ${ROUNDS}\n`);
const rows = [];
for (const [path, label] of CASES) {
  try { rows.push({ label, ...(await rate(path)) }); }
  catch (e) { console.log(`  ${label}: ${e.message}`); }
}
const best = Math.max(...rows.map((r) => r.rate));
for (const r of rows.sort((a, b) => b.rate - a.rate)) {
  console.log(`  ${r.label.padEnd(24)} ${(r.rate / 1000).toFixed(0).padStart(6)} kH/s   ` +
              `${r.us.toFixed(3)} us/hash   ${String(r.bytes).padStart(7)} B   ${(r.rate / best).toFixed(2)}x`);
}
