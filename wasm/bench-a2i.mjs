#!/usr/bin/env node
/**
 * bench-a2i.mjs — Argon2id's fill core in WAT, measured against the official module.
 *
 * Argon2id is memory-hard: m=19456 KiB means 38,912 blocks per hash, and the
 * block-filling function is ~99.9% of the work (H0 and H' are a few dozen
 * BLAKE2b compressions). So a per-block rate converts directly into an
 * equivalent hashes/s, and that is what this compares.
 *
 * The official modules are timed with `anubis_validate(nonce, difficulty)` — one
 * whole Argon2id hash per call — because their `anubis_work` loops until it finds
 * a solution and cannot be interrupted at a useful granularity.
 *
 *   node wasm/bench-a2i.mjs [--blocks 2000]
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OFFICIAL = process.env.ANUBIS_WASM_DIR ??
  '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm';
const BLOCKS_PER_HASH = 38912;          // m = 19456 KiB, t = 2, p = 1
const CHALLENGE = '00112233445566778899aabbccddeeff';

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const BLOCKS = Number(flag('blocks', 2000));
const fmt = (n) => n.toLocaleString('en-US', { maximumFractionDigits: n < 10 ? 3 : 0 });

/* ------------------------------------------------- our WAT fill_block */

const { instance: fill } = await WebAssembly.instantiate(readFileSync(join(HERE, 'argon2_fill.wasm')), {});
const ex = fill.exports;
// The arena: exactly what a real Argon2id run mixes — m = 19456 blocks of 1 KiB,
// which is ~19 MiB and does not fit in any cache. Filling three fixed blocks in a
// loop measures the arithmetic only; that is the mistake the first version of
// this benchmark made, and it flattered the hand-written version by ~5x.
const ARENA = 2048;
const DV = new DataView(ex.memory.buffer);
const BLOCKS_M = 19456;
const blockAddr = (b) => ARENA + (b % BLOCKS_M) * 1024;
for (let b = 0; b < BLOCKS_M; b++) {
  for (let i = 0; i < 128; i++) DV.setBigUint64(blockAddr(b) + 8 * i, BigInt(b * 128 + i), true);
}
const DST = blockAddr(0), PREV = blockAddr(1), REF = blockAddr(2);

// warm-up matters as much here as for the official modules: keep the best of
// three passes so the tier-up compiler is not part of the number
// pseudo-random block references, deterministic
let seed = 0x243f6a88;
const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % BLOCKS_M; };
ex.fill_block(blockAddr(10), blockAddr(11), blockAddr(12), 0);
let ns = Infinity;
for (let rep = 0; rep < 3; rep++) {
  const t0 = process.hrtime.bigint();
  for (let n = 0; n < BLOCKS; n++) {
    const dst = blockAddr(16 + n);
    ex.fill_block(dst, blockAddr(rnd()), blockAddr(rnd()), n & 1);
  }
  ns = Math.min(ns, Number(process.hrtime.bigint() - t0));
}
const perBlock = ns / BLOCKS;
const fillHashesPerSecond = 1e9 / (perBlock * BLOCKS_PER_HASH);

/* ------------------------------------------------- the official modules */

async function official(label) {
  const path = join(OFFICIAL, `${label}/argon2id.wasm`);
  if (!existsSync(path)) return null;
  const { instance } = await WebAssembly.instantiate(readFileSync(path),
    { anubis: { anubis_update_nonce: () => {} } });
  const ex = instance.exports;
  const ch = Buffer.from(CHALLENGE, 'hex');
  new Uint8Array(ex.memory.buffer).set(ch, ex.data_ptr());
  ex.set_data_length(ch.length);
  // Two untimed passes first: the first call allocates the 19 MiB arena and the
  // wasm tier-up compiler is still on its baseline tier, so timing an early call
  // measures warm-up, not throughput. (Getting this wrong once is how the first
  // version of this file reported a 4x loss that was mostly compilation.)
  ex.anubis_validate(0, 1);
  ex.anubis_validate(1, 1);
  let best = Infinity;
  for (let rep = 0; rep < 3; rep++) {
    const s = process.hrtime.bigint();
    ex.anubis_validate(100 + rep, 64);
    best = Math.min(best, Number(process.hrtime.bigint() - s) / 1e9);
  }
  return { label, seconds: best, hps: 1 / best, bytes: readFileSync(path).length };
}

const officialResults = [];
for (const label of ['baseline', 'simd128']) {
  const r = await official(label);
  if (r) officialResults.push(r);
}

/* --------------------------------------------------------------- report */

console.log(`Argon2id — m=19456 KiB, t=2, p=1, i.e. ${fmt(BLOCKS_PER_HASH)} blocks per hash`);
console.log(`fill_block measured over ${fmt(BLOCKS)} blocks x 3 passes, best of three\n`);
console.log(`  WAT fill_block                ${(perBlock / 1000).toFixed(2)} us/block  ` +
            `-> ${fmt(fillHashesPerSecond)} hashes/s equivalent`);
for (const o of officialResults) {
  const perBlockOfficial = (o.seconds * 1e9) / BLOCKS_PER_HASH;
  console.log(`  official ${o.label.padEnd(9)} (whole hash)  ${(o.seconds * 1e3).toFixed(1)} ms/hash ` +
              `-> ${fmt(o.hps)} hashes/s   (${(perBlockOfficial / 1000).toFixed(2)} us/block)`);
}

console.log('\nper-block comparison');
for (const o of officialResults) {
  const perBlockOfficial = (o.seconds * 1e9) / BLOCKS_PER_HASH;
  const ratio = perBlockOfficial / perBlock;
  console.log(`  vs official ${o.label.padEnd(9)}: ${ratio >= 1 ? '+' : ''}${ratio.toFixed(2)}x ` +
              `${ratio >= 1 ? 'faster' : 'slower'}`);
}
console.log('\nBoth sides now do the same thing: mix 1 KiB blocks at pseudo-random positions across');
console.log('a 19 MiB arena, so the numbers include the memory traffic that makes Argon2id');
console.log('memory-hard. Ours covers the mixing loop only; H0 and H\' (a few dozen BLAKE2b');
console.log('compressions, well under 0.1% of the work) are not in it, which is the one');
console.log('remaining asymmetry and it is in our favour by <0.1%.');
