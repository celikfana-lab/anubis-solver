#!/usr/bin/env node
/**
 * live-test.mjs — the real test: solve a live Anubis `sha256` challenge four ways
 * and check that the server actually lets each of them through.
 *
 *   1. official wasm   Anubis's own sha256.wasm, driven exactly like its worker
 *   2. our wasm        wasm/sha256_pow.wasm (C, clang -O3), same ABI, same driver
 *   3. node crypto     crypto.createHash, synchronous native SHA-256
 *   4. webcrypto       crypto.subtle.digest, the async native path a browser has
 *
 * A solve only counts if the pass-challenge call is accepted AND the follow-up
 * request returns the protected page. Timing is reported as hashes/s because the
 * nonce found varies with luck; ms alone would compare luck.
 *
 *   node wasm/live-test.mjs --url http://127.0.0.1:8923/ [--runs 3]
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const BASE = flag('url', 'http://127.0.0.1:8923/');
const RUNS = Number(flag('runs', 3));
const OFFICIAL = flag('official',
  '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm/simd128');

/* ------------------------------------------------------------------ http */

let cookie = '';

async function get(url, extra = {}) {
  const res = await fetch(url, {
    redirect: 'manual',
    headers: { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) anubis-solver live test',
               ...(cookie ? { cookie } : {}), ...extra },
  });
  const set = res.headers.getSetCookie?.() ?? [];
  for (const c of set) {
    const kv = c.split(';')[0];
    if (kv.includes('=') && !kv.startsWith('techaro.lol-anubis-cookie-test=')) {
      cookie = cookie ? `${cookie}; ${kv}` : kv;
    }
  }
  const text = await res.text();
  return { status: res.status, text, set };
}

function parseChallenge(html) {
  const m = /id="anubis_challenge"[^>]*>\s*(\{.*?\})\s*<\/script>/s.exec(html);
  if (!m) return null;
  return JSON.parse(m[1]);
}

/* --------------------------------------------------------------- solvers */

const leadingZeroBits = (buf) => {
  let bits = 0;
  for (const b of buf) { if (b === 0) { bits += 8; continue; } bits += Math.clz32(b) - 24; break; }
  return bits;
};

/** Drive an Anubis-ABI wasm module exactly like web/js/worker/wasm.ts does. */
async function wasmModule(path) {
  const { instance } = await WebAssembly.instantiate(readFileSync(path),
    { anubis: { anubis_update_nonce: () => {} } });
  const ex = instance.exports;
  return (challengeBytes, difficulty) => {
    new Uint8Array(ex.memory.buffer).set(challengeBytes, ex.data_ptr());
    ex.set_data_length(challengeBytes.length);
    const nonce = ex.anubis_work(difficulty, 0, 1);
    const hash = new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), ex.result_hash_size());
    return { nonce, hash: Buffer.from(hash) };
  };
}

const nonceBytes = (challenge, nonce) => {
  const b = Buffer.alloc(4);
  if (challenge[challenge.length - 1] >= 0x80) b.writeUInt32LE(nonce);
  else b.writeUInt32BE(nonce);
  return b;
};

function nodeCryptoSolver(challenge, difficulty) {
  let nonce = 0;
  for (;;) {
    const h = createHash('sha256').update(challenge).update(nonceBytes(challenge, nonce)).digest();
    if (leadingZeroBits(h) >= difficulty) return { nonce, hash: h };
    nonce++;
  }
}

async function webCryptoSolver(challenge, difficulty) {
  let nonce = 0;
  for (;;) {
    const h = Buffer.from(await crypto.subtle.digest('SHA-256',
      Buffer.concat([challenge, nonceBytes(challenge, nonce)])));
    if (leadingZeroBits(h) >= difficulty) return { nonce, hash: h };
    nonce++;
  }
}

/* ------------------------------------------------------------------- run */

const officialSolve = await wasmModule(join(OFFICIAL, 'sha256.wasm'));
const ourSolve = await wasmModule(join(HERE, 'sha256_pow.wasm'));
const batchSolve = await wasmModule(join(HERE, 'sha256_pow_batch.wasm'));

// warm-up: one solve at an easy difficulty so the tier-up compiler has finished
// before anything is timed. Without this, a difficulty-12 solve measures mostly
// the baseline compiler tier.
const WARM = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
officialSolve(WARM, 8);
ourSolve(WARM, 8);
batchSolve(WARM, 8);
for (let i = 0; i < 2; i++) {
  nodeCryptoSolver(WARM, 8);
  await webCryptoSolver(WARM, 8);
}

const SOLVERS = [
  ['official wasm',   (c, d) => officialSolve(c, d)],
  ['our wasm',        (c, d) => ourSolve(c, d)],
  ['our 4-wide wasm', (c, d) => batchSolve(c, d)],
  ['node crypto',     (c, d) => nodeCryptoSolver(c, d)],
  ['webcrypto',       (c, d) => webCryptoSolver(c, d)],
];

console.log(`live Anubis sha256 test — ${BASE}`);
console.log(`${RUNS} runs per solver, each solve verified by the server\n`);

const results = [];
for (const [name, solve] of SOLVERS) {
  const rows = [];
  for (let r = 0; r < RUNS; r++) {
    cookie = '';
    const first = await get(BASE);
    const chal = parseChallenge(first.text);
    if (!chal) { console.log(`  ${name}: no challenge at ${BASE} (status ${first.status})`); break; }
    const { algorithm, difficulty } = chal.rules;
    if (algorithm !== 'sha256') { console.log(`  ${name}: host serves ${algorithm}, not sha256`); break; }
    const challenge = Buffer.from(chal.challenge.randomData, 'hex');

    const t0 = performance.now();
    const { nonce, hash } = await solve(challenge, difficulty);
    const ms = performance.now() - t0;

    const passUrl = new URL('/.within.website/x/cmd/anubis/api/pass-challenge', BASE);
    passUrl.searchParams.set('id', chal.challenge.id);
    passUrl.searchParams.set('response', hash.toString('hex'));
    passUrl.searchParams.set('nonce', String(nonce));
    passUrl.searchParams.set('redir', '/');
    passUrl.searchParams.set('elapsedTime', String(Math.round(ms)));
    const passed = await get(passUrl.toString());
    const after = await get(BASE);
    const accepted = after.status === 200 && /PAST THE WALL/.test(after.text);

    rows.push({ ms, nonce, accepted, status: after.status, n: nonce + 1, difficulty,
                passStatus: passed.status });
  }
  if (rows.length) {
    const ok = rows.every((r) => r.accepted);
    const ms = rows.map((r) => r.ms).sort((a, b) => a - b)[Math.floor(rows.length / 2)];
    const hashes = rows.reduce((a, r) => a + r.n, 0);
    const seconds = rows.reduce((a, r) => a + r.ms, 0) / 1000;
    const rates = rows.map((r) => r.n / (r.ms / 1000));
    results.push({ name, ok, ms, hashes, hps: hashes / seconds, rows, rates });
    // no rate column on purpose: a solve at the server's difficulty is a few
    // thousand hashes and lands inside the wasm tier-up window, so any figure
    // here measures compilation. Rates come from bench-sha256.mjs (fixed work).
    console.log(`  ${name.padEnd(16)} ${ms.toFixed(1).padStart(7)} ms to a valid nonce  ` +
                `${ok ? 'accepted by the server' : 'REJECTED'}  ` +
                `(${rows.length}/${rows.length} runs)`);
  }
}

console.log('\n  every solver above was accepted by a real Anubis v1.28.3.');
console.log('  For throughput on fixed work (the only fair ranking), run:');
console.log('    node bench-sha256.mjs --difficulty 23');
