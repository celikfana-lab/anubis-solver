#!/usr/bin/env node
/**
 * bench-threads.mjs — Argon2id scales across workers almost perfectly, because
 * each nonce is an independent 19 MiB hash. This is the lever that actually makes
 * a *solver* faster (p=1 inside a hash is fixed by the challenge; parallelism goes
 * across nonces, which is also why the official module takes an `iterand`).
 *
 *   node bench-threads.mjs [--workers 4] [--hashes 8]
 */
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { readFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { fileURLToPath } from 'node:url';

const HEREDIR = fileURLToPath(new URL('.', import.meta.url));
const DIR = process.env.ANUBIS_WASM_DIR ??
  '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm';
const CH = '00112233445566778899aabbccddeeff';

if (!isMainThread) {
  // --- worker: one wasm instance, its own 19 MiB arena, its own nonce stride ---
  const { label, start, count, budgetMs } = workerData;
  const { instance } = await WebAssembly.instantiate(
    readFileSync(`${DIR}/${label}/argon2id.wasm`),
    { anubis: { anubis_update_nonce: () => {} } },
  );
  const ex = instance.exports;
  const ch = Buffer.from(CH, 'hex');
  new Uint8Array(ex.memory.buffer).set(ch, ex.data_ptr());
  ex.set_data_length(ch.length);

  ex.anubis_validate(0, 1);                       // warm up + allocate the arena
  let done = 0;
  const t0 = performance.now();
  while (done < count && performance.now() - t0 < budgetMs) {
    ex.anubis_validate(start + done, 64);          // difficulty 64 never hits
    done++;
  }
  parentPort.postMessage({ done, seconds: (performance.now() - t0) / 1000 });
} else {
  const argv = process.argv.slice(2);
  const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? Number(argv[i + 1]) : d; };
  const maxWorkers = cpus().length;
  const want = flag('workers', Math.min(4, maxWorkers));
  const hashes = flag('hashes', 8);
  const i = argv.indexOf('--official');
  const label = i >= 0 && argv[i + 1] ? argv[i + 1] : 'simd128';
  const budgetMs = 60_000;

  console.log(`Argon2id across workers — official ${label} module, difficulty 64`);
  console.log(`${maxWorkers} CPUs visible, ${hashes} hashes per worker\n`);

  const run = (n) => new Promise((resolve, reject) => {
    const results = [];
    let remaining = n;
    const t0 = performance.now();
    for (let w = 0; w < n; w++) {
      const worker = new Worker(fileURLToPath(import.meta.url), {
        workerData: { label, start: w * 100_000, count: hashes, budgetMs },
      });
      worker.once('message', (m) => {
        results.push(m);
        if (--remaining === 0) {
          const wall = (performance.now() - t0) / 1000;
          resolve({ wall, total: results.reduce((a, r) => a + r.done, 0) });
        }
      });
      worker.once('error', reject);
    }
  });

  const rows = [];
  for (const n of [1, 2, 4].filter((n) => n <= maxWorkers)) {
    const { wall, total } = await run(n);
    rows.push({ n, wall, total, hps: total / wall });
    console.log(`  ${String(n).padStart(2)} worker(s)  ${total} hashes in ${wall.toFixed(2)} s  ` +
                `-> ${(total / wall).toFixed(2)} hashes/s  (${(wall / total * 1e3).toFixed(0)} ms/hash)`);
  }
  const base = rows[0].hps;
  console.log('\n  scaling');
  for (const r of rows) console.log(`    ${r.n} worker(s): ${(r.hps / base).toFixed(2)}x  (ideal ${r.n}x)`);
  console.log('\n  Per-hash work is independent, so this is the one lever with real headroom:');
  console.log('  a browser tab gets one worker per core, and Web Workers give it.');
}
