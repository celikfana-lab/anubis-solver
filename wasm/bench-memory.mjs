#!/usr/bin/env node
/**
 * bench-memory.mjs — where Argon2id's cost actually goes: the arena size.
 *
 * The same fill_block, the same number of blocks, only the working set changes.
 * If the time per block is flat until the cache runs out and then climbs, the
 * remaining cost is memory, not arithmetic — which decides what to optimise.
 *
 *   node bench-memory.mjs [--blocks 20000]
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const WASM = fileURLToPath(new URL('./argon2_fill.wasm', import.meta.url));
const argv = process.argv.slice(2);
const BLOCKS = Number(argv[argv.indexOf('--blocks') + 1] ?? 20000);
const ARENA = 4096;

const { instance } = await WebAssembly.instantiate(readFileSync(WASM), {});
const ex = instance.exports;
const need = Math.ceil((ARENA + 19456 * 1024) / 65536) + 1;
ex.memory.grow(Math.max(0, need - ex.memory.buffer.byteLength / 65536));
const dv = new DataView(ex.memory.buffer);
const blockAddr = (b, arenaBlocks) => ARENA + (b % arenaBlocks) * 1024;

// sizes that walk from L2 into DRAM (a typical laptop: 1-2 MiB L2, 8-32 MiB L3)
const SIZES = [
  [  16, '16 KiB'], [  64, '64 KiB'], [ 256, '256 KiB'], [1024, '1 MiB'],
  [4096, '4 MiB'], [16384, '16 MiB'], [19456, '19 MiB (real m)'],
];

console.log(`Argon2id fill_block vs working set — ${BLOCKS} blocks, best of three\n`);
const rows = [];
for (const [arenaBlocks, label] of SIZES) {
  for (let b = 0; b < arenaBlocks; b++) {
    dv.setBigUint64(blockAddr(b, arenaBlocks), BigInt(b), true);   // touch one word per block
  }
  let seed = 0x243f6a88;
  const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % arenaBlocks; };
  ex.fill_block(blockAddr(0, arenaBlocks), blockAddr(1, arenaBlocks), blockAddr(2, arenaBlocks), 0);
  let best = Infinity;
  for (let rep = 0; rep < 3; rep++) {
    seed = 0x243f6a88;
    const t0 = process.hrtime.bigint();
    for (let n = 0; n < BLOCKS; n++) {
      ex.fill_block(blockAddr(n + 16, arenaBlocks), blockAddr(rnd(), arenaBlocks),
                    blockAddr(rnd(), arenaBlocks), n & 1);
    }
    best = Math.min(best, Number(process.hrtime.bigint() - t0) / BLOCKS);
  }
  rows.push({ label, ns: best });
  console.log(`  ${label.padEnd(16)} ${(best / 1000).toFixed(2)} us/block   ` +
              `${(1e9 / (best * 38912)).toFixed(1)} hashes/s if this were the whole hash`);
}
const flat = rows[0].ns;
console.log('\n  cost of leaving the cache');
for (const r of rows.slice(1)) console.log(`    ${r.label.padEnd(16)} ${(r.ns / flat).toFixed(2)}x the 16 KiB time`);
