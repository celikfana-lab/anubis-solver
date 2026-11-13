#!/usr/bin/env node
/**
 * bench.mjs — benchmark HashX in WebAssembly, three ways.
 *
 *   1. hashx_jit.wasm     the challenge program compiled to straight-line WAT
 *                         (tools/gen_hashx_wat.py): no interpreter
 *   2. baseline/hashx.wasm the official Anubis module, as shipped
 *   3. simd128/hashx.wasm  the official module, SIMD build
 *
 *    node wasm/bench.mjs                      # default 2M hashes each
 *    node wasm/bench.mjs --hashes 8000000
 *    node wasm/bench.mjs --official /path/to/anubis/web/static/wasm
 *
 * The official module's `anubis_work(difficulty, nonce, iterand)` loops until it
 * finds a hit and reports progress every 1024 nonces through the
 * `anubis.anubis_update_nonce` import. To measure throughput without waiting for
 * a real solution, difficulty is set to 64 (unreachable) and the import throws
 * after the planned number of callbacks — a JS throw unwinds the wasm frame, so
 * the call returns and we have our timing.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = dirname(HERE);

/** case 0 of beyond/vectors/hx_vectors.hex: the challenge and its keys, and the
 *  four digest words the C engine produces for nonce 0 (the reference). */
const CHALLENGE_HEX = '6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d';
const EXPECTED = [0x046eec4a54205736n, 0x92fa2440753b292en, 0x93f4121c1d4c2b5cn, 0xe39da32f2048533fn];

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : fallback;
};

const WANT_HASHES = Number(flag('hashes', 2_000_000));
const OFFICIAL_DIR = flag('official', null) ?? process.env.ANUBIS_WASM_DIR ??
  '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/web/static/wasm';

const fmt = (n) => n.toLocaleString('en-US', { maximumFractionDigits: 0 });
const hex = (b) => Buffer.from(b).toString('hex');

/** Load a module, instantiate it with the given imports. */
async function instantiate(path, imports = {}) {
  const bytes = readFileSync(path);
  const { instance } = await WebAssembly.instantiate(bytes, imports);
  return instance;
}

/* ------------------------------------------------------- our JIT module */

function benchJit(hashes) {
  const instance = async () => instantiate(join(HERE, 'hashx_jit.wasm'));
  return instance().then((inst) => {
    const { hash, solve, memory } = inst.exports;

    // --- correctness first: the digest for nonce 0 must match the C engine ---
    const lz = Number(hash(0n));
    const words = [];
    const view = new DataView(memory.buffer);
    for (let i = 0; i < 4; i++) words.push(view.getBigUint64(8 * i, true));
    const digestOk = words.every((w, i) => w === EXPECTED[i]);
    const lzOk = lz === leadingZeroBits(Buffer.from(words.flatMap((w) => {
      const b = Buffer.alloc(8);
      b.writeBigUInt64LE(w);
      return [...b];
    })));

    // --- throughput: difficulty 64 never hits, so it hashes exactly `hashes` ---
    solve(0n, 64n, 1n);          // warm up the tier-up compiler
    const started = process.hrtime.bigint();
    const hit = solve(0n, 64n, BigInt(hashes));
    const ns = Number(process.hrtime.bigint() - started);
    return { digestOk, lzOk, lz, words, hit: Number(hit), seconds: ns / 1e9, hashes };
  });
}

function leadingZeroBits(buf) {
  let bits = 0;
  for (const byte of buf) {
    if (byte === 0) { bits += 8; continue; }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

/* ---------------------------------------------------- official Anubis module */

async function benchOfficial(path, hashes) {
  const challenge = Buffer.from(CHALLENGE_HEX, 'hex');
  let calls = 0;
  let budget = 0;
  let started = 0;
  let ns = 0;

  // The module reports every 1024 nonces; throw once the budget is spent.
  const imports = {
    anubis: {
      anubis_update_nonce: () => {
        calls++;
        if (calls === 1) started = Number(process.hrtime.bigint());
        if (calls >= budget) {
          ns = Number(process.hrtime.bigint()) - started;
          throw new Error('__anubis_budget__');
        }
      },
    },
  };

  const inst = await instantiate(path, imports);
  const ex = inst.exports;
  const mem = new DataView(ex.memory.buffer);
  const dataPtr = Number(ex.data_ptr());
  for (let i = 0; i < challenge.length; i++) mem.setUint8(dataPtr + i, challenge[i]);
  ex.set_data_length(challenge.length);

  // One callback per 1024 nonces = 1024 hashes.
  budget = Math.ceil(hashes / 1024) + 1;
  const wallStart = Number(process.hrtime.bigint());
  try {
    ex.anubis_work(64, 0, 1);
  } catch (e) {
    if (!/__anubis_budget__/.test(String(e))) throw e;
  }
  const wallNs = Number(process.hrtime.bigint()) - wallStart;
  const done = Math.min(calls, Math.ceil(hashes / 1024)) * 1024;
  return { hashes: done, seconds: wallNs / 1e9 };
}

/* --------------------------------------------------------------- reporting */

function row(name, hashes, seconds, note = '') {
  const hps = hashes / seconds;
  console.log(
    `  ${name.padEnd(30)} ${fmt(hps).padStart(14)} hashes/s  ` +
    `(${(seconds * 1e3).toFixed(1)} ms for ${fmt(hashes)})${note ? '  ' + note : ''}`,
  );
  return hps;
}

const main = async () => {
  console.log(`HashX in WebAssembly — ${fmt(WANT_HASHES)} hashes per measurement`);
  console.log(`challenge ${CHALLENGE_HEX.slice(0, 24)}… (case 0 of beyond/vectors/hx_vectors.hex)\n`);

  /* --- our JIT --- */
  console.log('the program compiled to straight-line WAT:');
  const jit = await benchJit(WANT_HASHES);
  console.log(`  digest for nonce 0 matches the C engine: ${jit.digestOk ? 'yes' : 'NO'}` +
              `  (${jit.words.map((w) => w.toString(16).padStart(16, '0')).join(' ')})`);
  console.log(`  leading zero bits: ${jit.lz} (${jit.lzOk ? 'consistent' : 'INCONSISTENT'}),` +
              ` solve() returned ${jit.hit} for difficulty 64 (expected -1)`);
  const jitRate = row('hashx_jit.wasm', jit.hashes, jit.seconds);
  const jitSize = readFileSync(join(HERE, 'hashx_jit.wasm')).length;
  const jitLines = readFileSync(join(HERE, 'hashx_jit.wat'), 'utf8').split('\n').length;

  /* --- the official modules --- */
  const official = [];
  for (const [label, rel] of [['baseline', 'baseline/hashx.wasm'], ['simd128', 'simd128/hashx.wasm']]) {
    const path = join(OFFICIAL_DIR, rel);
    if (!existsSync(path)) {
      console.log(`\nofficial ${label}: not found at ${path} (pass --official <dir>)`);
      continue;
    }
    const r = await benchOfficial(path, WANT_HASHES);
    const size = readFileSync(path).length;
    official.push({ label, rate: row(`official ${label}/hashx.wasm`, r.hashes, r.seconds), size });
  }

  console.log('\nsummary');
  console.log(`  hashx_jit.wasm is ${fmt(jitSize)} bytes, generated from ${fmt(jitLines)} lines of WAT`);
  for (const o of official) {
    const ratio = jitRate / o.rate;
    console.log(
      `  vs official ${o.label.padEnd(9)} (${fmt(o.size)} bytes): ` +
      `${ratio >= 1 ? '+' : ''}${ratio.toFixed(2)}x ${ratio >= 1 ? 'faster' : 'slower'}`,
    );
  }
  console.log('\n  reference: the C engine does ~571 cycles/hash, i.e. ~1.75 M hashes/s' +
              ' per core lane at ~1 GHz and ~224 M hashes/s across 128 lanes (SPEED.md).');
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
