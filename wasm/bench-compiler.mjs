#!/usr/bin/env node
/**
 * bench-compiler.mjs — hand-written WAT vs the same code compiled from Rust.
 *
 * Both are correct (checked against fill_vectors.txt, which comes from compiling
 * the vendored C reference). What differs is who scheduled the instructions.
 *
 * Two regimes, because they disagree:
 *
 *   cache-resident  three fixed 1 KiB blocks: measures the arithmetic only
 *   memory-bound    references scattered across the 19 MiB arena Argon2id really
 *                   uses: measures what a real hash spends its time on
 *
 *   node bench-compiler.mjs [--blocks 3000]
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const VEC = fileURLToPath(new URL('./fill_vectors.txt', import.meta.url));
const BLOCKS_PER_HASH = 38912;
const BLOCKS_M = 19456;                 // m = 19456 KiB
const ARENA = 4096;                     // keeps clear of stack/data in every module

const argv = process.argv.slice(2);
const BLOCKS = Number(argv[argv.indexOf('--blocks') + 1] ?? 3000);

/* --- reference vectors --- */
const lines = readFileSync(VEC, 'utf8').trim().split('\n');
const trials = [];
{
  let i = 0;
  while (i < lines.length) {
    const h = /^trial (\d+) xor (\d+)$/.exec(lines[i++].trim());
    const read = (name) => {
      if (lines[i++].trim() !== name) throw new Error('bad vector file');
      const w = [];
      while (w.length < 128) w.push(...lines[i++].trim().split(/\s+/));
      return w;
    };
    trials.push({ withXor: Number(h[2]), prev: read('prev'), ref: read('ref'), next: read('next'), result: read('result') });
  }
}

const CASES = [
  ['WAT, scalar', fileURLToPath(new URL('./argon2_fill.wasm', import.meta.url))],
  ['WAT, v128 (hand)', fileURLToPath(new URL('./argon2_fill_simd.wasm', import.meta.url))],
  ['rustc, scalar', fileURLToPath(new URL('./compiler/fill_scalar.wasm', import.meta.url))],
  ['rustc, +simd128', fileURLToPath(new URL('./compiler/fill_simd.wasm', import.meta.url))],
  ['clang C, -O3 (chosen)', fileURLToPath(new URL('./argon2_fill_c.wasm', import.meta.url))],
  ['clang C, -O3 -msimd128', fileURLToPath(new URL('./compiler/fill_c_simd.wasm', import.meta.url))],
];

const blockAddr = (b) => ARENA + (b % BLOCKS_M) * 1024;

async function prepare(path) {
  const { instance } = await WebAssembly.instantiate(readFileSync(path), {});
  const ex = instance.exports;
  // grow to hold the 19 MiB arena plus whatever the module already uses
  const need = Math.ceil((ARENA + BLOCKS_M * 1024) / 65536) + 1;
  const have = ex.memory.buffer.byteLength / 65536;
  if (have < need) ex.memory.grow(need - have);
  return ex;
}

function verify(ex) {
  const dv = new DataView(ex.memory.buffer);
  const at = ARENA + BLOCKS_M * 1024;              // scratch above the arena
  const write = (a, ws) => ws.forEach((w, k) => dv.setBigUint64(a + 8 * k, BigInt('0x' + w), true));
  for (const t of trials) {
    write(at, t.prev); write(at + 1024, t.ref); write(at + 2048, t.next);
    ex.fill_block(at + 2048, at, at + 1024, t.withXor);
    for (let k = 0; k < 128; k++) {
      if (dv.getBigUint64(at + 2048 + 8 * k, true).toString(16).padStart(16, '0') !== t.result[k]) return false;
    }
  }
  return true;
}

function timeResident(ex) {
  const dv = new DataView(ex.memory.buffer);
  for (let k = 0; k < 128; k++) { dv.setBigUint64(5120 + 8 * k, BigInt(k + 1), true); dv.setBigUint64(6144 + 8 * k, BigInt(k * 3 + 7), true); }
  ex.fill_block(4096, 5120, 6144, 0);
  let best = Infinity;
  for (let rep = 0; rep < 3; rep++) {
    const t0 = process.hrtime.bigint();
    for (let n = 0; n < BLOCKS; n++) ex.fill_block(4096, 5120, 6144, n & 1);
    best = Math.min(best, Number(process.hrtime.bigint() - t0) / BLOCKS);
  }
  return best;
}

function timeMemoryBound(ex) {
  const dv = new DataView(ex.memory.buffer);
  for (let b = 0; b < BLOCKS_M; b++) for (let i = 0; i < 128; i++) dv.setBigUint64(blockAddr(b) + 8 * i, BigInt(b * 128 + i), true);
  let seed = 0x243f6a88;
  const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % BLOCKS_M; };
  ex.fill_block(blockAddr(10), blockAddr(11), blockAddr(12), 0);
  let best = Infinity;
  for (let rep = 0; rep < 3; rep++) {
    seed = 0x243f6a88;
    const t0 = process.hrtime.bigint();
    for (let n = 0; n < BLOCKS; n++) ex.fill_block(blockAddr(16 + n), blockAddr(rnd()), blockAddr(rnd()), n & 1);
    best = Math.min(best, Number(process.hrtime.bigint() - t0) / BLOCKS);
  }
  return best;
}

const ROUNDS = 5;
const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };

const impls = [];
for (const [label, path] of CASES) {
  const ex = await prepare(path);
  impls.push({ label, ex, bytes: readFileSync(path).length, ok: verify(ex), resident: [], bound: [] });
}

// interleaved rounds, median per implementation: a sequential sweep lets wasm
// tier-up and GC drift the ranking, which is what made earlier runs disagree
for (let r = 0; r < ROUNDS; r++) {
  for (const im of impls) {
    im.resident.push(timeResident(im.ex));
    im.bound.push(timeMemoryBound(im.ex));
  }
  // one warm-up GC pause between rounds where the runtime exposes it
  if (global.gc) global.gc();
}

console.log(`Argon2id fill_block — ${BLOCKS} blocks, ${ROUNDS} interleaved rounds, median\n`);
console.log('  implementation              cache-resident   memory-bound (19 MiB)     size');
const rows = impls.map((im) => ({
  label: im.label, bytes: im.bytes, ok: im.ok,
  resident: median(im.resident), bound: median(im.bound),
}));
for (const r of rows) {
  console.log(`  ${r.label.padEnd(26)} ${(r.resident / 1000).toFixed(2).padStart(6)} us/block  ` +
              `${(r.bound / 1000).toFixed(2).padStart(8)} us/block  ${String(r.bytes).padStart(7)} B  ${r.ok ? 'correct' : 'WRONG'}`);
}
const best = Math.min(...rows.map((r) => r.bound));
console.log('\n  relative to the fastest memory-bound implementation:');
for (const r of [...rows].sort((a, b) => a.bound - b.bound)) {
  console.log(`    ${r.label.padEnd(26)} ${(r.bound / best).toFixed(2)}x   ` +
    `(${(1e9 / (r.bound * BLOCKS_PER_HASH)).toFixed(1)} hashes/s if this were the whole hash)`);
}
