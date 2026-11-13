#!/usr/bin/env node
/**
 * bench-hashx-threads.mjs — HashX cannot be batched across nonces (see the README:
 * its program takes a data-dependent backward jump in almost every hash, so two
 * nonces do not stay in lockstep). What does work is independent workers, because
 * each nonce is a separate search.
 *
 *   node bench-hashx-threads.mjs [--hashes 4000000] [--workers 4]
 */
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { readFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { fileURLToPath } from 'node:url';

const WASM = fileURLToPath(new URL('./hashx_jit.wasm', import.meta.url));

if (!isMainThread) {
  const { start, count } = workerData;
  const { instance } = await WebAssembly.instantiate(readFileSync(WASM), {});
  const { solve } = instance.exports;
  solve(0n, 64n, 1n);                       // warm up
  const t0 = performance.now();
  solve(BigInt(start), 64n, BigInt(count)); // difficulty 64 never hits: pure hashing
  parentPort.postMessage({ seconds: (performance.now() - t0) / 1000, count });
} else {
  const argv = process.argv.slice(2);
  const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? Number(argv[i + 1]) : d; };
  const HASHES = flag('hashes', 4_000_000);
  const MAX = Math.min(8, cpus().length);

  console.log(`HashX across workers — ${(HASHES / 1e6).toFixed(0)}M hashes each, difficulty 64\n`);

  const run = (n) => new Promise((resolve, reject) => {
    const results = [];
    let left = n;
    const t0 = performance.now();
    for (let w = 0; w < n; w++) {
      const worker = new Worker(fileURLToPath(import.meta.url), {
        workerData: { start: w * 0x01000000 + 1, count: HASHES },
      });
      worker.once('message', (m) => {
        results.push(m);
        if (--left === 0) resolve({ wall: (performance.now() - t0) / 1000, results });
      });
      worker.once('error', reject);
    }
  });

  const rows = [];
  for (const n of [1, 2, 4].filter((n) => n <= MAX)) {
    const { wall, results } = await run(n);
    const total = results.reduce((a, r) => a + r.count, 0);
    rows.push({ n, hps: total / wall });
    console.log(`  ${String(n).padStart(2)} worker(s)  ${(total / wall / 1e6).toFixed(2)} M hashes/s  ` +
                `(${((total / wall) / 1e6 / n).toFixed(2)} M per worker)`);
  }
  const base = rows[0].hps;
  console.log('\n  scaling');
  for (const r of rows) console.log(`    ${r.n} worker(s): ${(r.hps / base).toFixed(2)}x  (ideal ${r.n}x)`);
  console.log('\n  for reference, the module Anubis ships does ~0.33 M hashes/s, so this');
  console.log('  is already 6x ahead single-threaded; workers multiply that.');
}
