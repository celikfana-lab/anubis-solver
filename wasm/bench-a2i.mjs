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
const DST = 4096, PREV = 5120, REF = 6144;
const dv = new DataView(ex.memory.buffer);
for (const [addr, seed] of [[PREV, 1], [REF, 2], [DST, 3]]) {
  for (let i = 0; i < 128; i++) dv.setBigUint64(addr + 8 * i, (BigInt(seed) << 56n) ^ BigInt(i), true);
}

ex.fill_block(DST, PREV, REF, 0);                       // warm up
let t0 = process.hrtime.bigint();
for (let n = 0; n < BLOCKS; n++) ex.fill_block(DST, PREV, REF, n & 1);
let ns = Number(process.hrtime.bigint() - t0);
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
  ex.anubis_validate(0, 1);                              // warm up + allocate
  const reps = 3;
  const s = process.hrtime.bigint();
  for (let i = 0; i < reps; i++) ex.anubis_validate(i, 64);
  const sec = Number(process.hrtime.bigint() - s) / 1e9;
  return { label, seconds: sec / reps, hps: reps / sec, bytes: readFileSync(path).length };
}

const officialResults = [];
for (const label of ['baseline', 'simd128']) {
  const r = await official(label);
  if (r) officialResults.push(r);
}

/* --------------------------------------------------------------- report */

console.log(`Argon2id — m=19456 KiB, t=2, p=1, i.e. ${fmt(BLOCKS_PER_HASH)} blocks per hash`);
console.log(`fill_block measured over ${fmt(BLOCKS)} blocks\n`);
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
console.log('\nOur number covers the block-mixing loop only: H0 and H\' (a few dozen BLAKE2b');
console.log('compressions, well under 0.1% of the work) are not in it. The official figure is a');
console.log('whole hash, so the comparison is generous to us by that margin, not the reverse.');
