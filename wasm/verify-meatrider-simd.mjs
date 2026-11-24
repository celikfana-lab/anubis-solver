#!/usr/bin/env node
/**
 * verify-meatrider-simd.mjs -- the 4-lane SIMD128 meatrider kernel must agree
 * with the scalar one, nonce for nonce, digest for digest.
 *
 * The scalar module (meatrider_pow.wasm) is the reference here; the challenge
 * construction it shares with src/meatrider/meatrider.c is what
 * verify-meatrider.mjs checks against node:crypto. This test asks the harder
 * comparison question: batching changes how many nonces are in flight, never
 * which one wins and never a byte of any digest.
 *
 * The per-nonce sweep uses anubis_work_limited(..., limit = 1), which leaves the
 * tested candidate's digest in the result buffer whether or not it met the
 * target. That turns both modules into "hash this one nonce and report it"
 * calls, so every digest -- not just the winners -- is compared.
 *
 *   node wasm/verify-meatrider-simd.mjs
 */
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

const files = {
  scalar: join(HERE, 'meatrider_pow.wasm'),
  simd: join(HERE, 'meatrider_simd.wasm'),
};
for (const [name, path] of Object.entries(files)) {
  if (!existsSync(path)) {
    console.error(`no ${name} module at ${path}`);
    process.exit(2);
  }
}

const scalar = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(files.scalar)), {}).exports;
const simd = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(files.simd)), {}).exports;

/* fixed challenges: the same input on every run, so a failure is reproducible */
const DATASETS = [
  '00112233445566778899aabbccddeeff0f1e2d3c4b5a69788796a5b4c3d2e1f0',
  'ffeeddccbbaa998877665544332211000102030405060708090a0b0c0d0e0f10',
  'deadbeefcafebabe0123456789abcdef5a5a5a5a3c3c3c3ca1a1a1a1f0f0f0f0',
].map((h) => Buffer.from(h, 'hex'));

const VERSION = 1;
const TIME = 1231006505;

/* --- the specification, independently, with node's own SHA-256 ------------ */
function compact(target) {
  let size = Math.ceil(target.toString(2).length / 8);
  let c = size <= 3 ? target << BigInt(8 * (3 - size)) : target >> BigInt(8 * (size - 3));
  if (c & 0x00800000n) {
    c >>= 8n;
    size += 1;
  }
  return Number(c | BigInt(size << 24));
}

function header(rd, difficulty, nonce) {
  const buf = Buffer.alloc(80);
  buf.writeUInt32LE(VERSION, 0);
  rd.copy(buf, 4);
  createHash('sha256').update(Buffer.concat([Buffer.from('meatrider'), rd])).digest().copy(buf, 36);
  buf.writeUInt32LE(TIME, 68);
  buf.writeUInt32LE(compact(1n << BigInt(256 - difficulty)), 72);
  buf.writeUInt32LE(nonce >>> 0, 76);
  return buf;
}

function bitcoinHash(rd, difficulty, nonce) {
  const h = createHash('sha256')
    .update(createHash('sha256').update(header(rd, difficulty, nonce)).digest())
    .digest();
  return Buffer.from(h).reverse();
}

function lz(buf) {
  let n = 0;
  for (const b of buf) {
    if (b === 0) {
      n += 8;
      continue;
    }
    return n + 8 - b.toString(2).length;
  }
  return n;
}

/* --- driving one module --------------------------------------------------- */
function setChallenge(ex, rd) {
  new Uint8Array(ex.memory.buffer).set(rd, ex.data_ptr());
  ex.set_data_length(rd.length);
}

function digest(ex) {
  return Buffer.from(
    new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), ex.result_hash_size()));
}

function run(ex, difficulty, nonce, iterand, limit) {
  const got = ex.anubis_work_limited(difficulty, nonce >>> 0, iterand >>> 0, limit >>> 0);
  return { nonce: got >>> 0, failed: got < 0, digest: digest(ex) };
}

function full(ex, difficulty, nonce, iterand) {
  const got = ex.anubis_work(difficulty, nonce >>> 0, iterand >>> 0);
  return { nonce: got >>> 0, digest: digest(ex) };
}

/* --- assertions ----------------------------------------------------------- */
let checks = 0;

function eq(label, got, want) {
  checks++;
  if (got !== want) {
    console.error(`FAIL ${label}\n  got  ${got}\n  want ${want}`);
    process.exit(1);
  }
}

function eqHex(label, got, want) {
  checks++;
  if (!got.equals(want)) {
    console.error(`FAIL ${label}\n  got  ${got.toString('hex')}\n  want ${want.toString('hex')}`);
    process.exit(1);
  }
}

function both(rd, difficulty) {
  setChallenge(scalar, rd);
  setChallenge(simd, rd);
  return difficulty;
}

/* 1. the same winning nonce and the same bytes for the winner, on every fixed
 *    challenge and at every difficulty the brief names ---------------------- */
for (const [di, rd] of DATASETS.entries()) {
  for (const difficulty of [1, 8, 12, 16]) {
    const base = 0x10000 + di * 0x1000 + difficulty * 7;
    both(rd, difficulty);
    const a = full(scalar, difficulty, base, 1);
    const b = full(simd, difficulty, base, 1);
    eq(`winner d=${difficulty} rd=${di}`, b.nonce, a.nonce);
    eqHex(`winner digest d=${difficulty} rd=${di}`, b.digest, a.digest);
    eqHex(`winner vs node d=${difficulty} rd=${di}`,
          a.digest, bitcoinHash(rd, difficulty, a.nonce));
    eq(`winner meets target d=${difficulty} rd=${di}`, lz(a.digest) >= difficulty, true);
  }
}

/* 2. every digest over a few hundred consecutive nonces. Starting just below
 *    2^32 also exercises the u32 wrap in the middle of a 4-lane batch. ------ */
const SWEEP = 300;
for (const [di, rd] of DATASETS.entries()) {
  both(rd, 8);
  for (let i = 0; i < SWEEP; i++) {
    const nonce = (0xffffffff - (SWEEP >> 1) + i) >>> 0;
    const a = run(scalar, 8, nonce, 1, 1);
    const b = run(simd, 8, nonce, 1, 1);
    eq(`sweep nonce rd=${di} i=${i}`, b.nonce, a.nonce);
    eqHex(`sweep digest rd=${di} nonce=${nonce}`, b.digest, a.digest);
    if (i % 10 === 0)
      eqHex(`sweep vs node rd=${di} nonce=${nonce}`,
            b.digest, bitcoinHash(rd, 8, nonce));
  }
}

/* 3. windows that are not a multiple of four: the SIMD kernel hashes four
 *    candidates but must only accept the first `limit` of them ------------- */
for (const limit of [1, 2, 3, 5, 6, 7, 13]) {
  const rd = DATASETS[limit % DATASETS.length];
  both(rd, 2);
  const a = run(scalar, 2, 0, 1, limit);
  const b = run(simd, 2, 0, 1, limit);
  eq(`partial window limit=${limit} nonce`, b.nonce, a.nonce);
  eqHex(`partial window limit=${limit} digest`, b.digest, a.digest);
}

/* 4. iterands other than one, including an iterand that wraps the nonce ----- */
for (const iterand of [0, 2, 3, 7, 0x80000001]) { /* 0 is promoted to 1 */
  for (const difficulty of [1, 8, 12]) {
    const rd = DATASETS[(iterand + difficulty) % DATASETS.length];
    both(rd, difficulty);
    const a = run(scalar, difficulty, 0xfffffff0, iterand, 200);
    const b = run(simd, difficulty, 0xfffffff0, iterand, 200);
    eq(`iterand ${iterand} d=${difficulty} nonce`, b.nonce, a.nonce);
    eqHex(`iterand ${iterand} d=${difficulty} digest`, b.digest, a.digest);
    if (!a.failed)
      eqHex(`iterand ${iterand} d=${difficulty} vs node`,
            a.digest, bitcoinHash(rd, difficulty, a.nonce));
  }
}

/* 5. an exhausted window leaves the last tested digest in both buffers ----- */
for (const limit of [0, 16, 17]) {
  const rd = DATASETS[1];
  both(rd, 30);
  const a = run(scalar, 30, 12345, 1, limit);
  const b = run(simd, 30, 12345, 1, limit);
  eq(`exhausted limit=${limit} nonce`, b.nonce, a.nonce);
  eq(`exhausted limit=${limit} failure`, b.failed, a.failed);
  eqHex(`exhausted limit=${limit} digest`, b.digest, a.digest);
}

/* 6. a reproducible rate, measured over an identical window. difficulty 255 is
 *    unattainable, so each call runs exactly N hashes and nothing else. N is a
 *    multiple of four so the SIMD kernel does no partial final batch. -------- */
const N = 1_000_000;
const ROUNDS = 5;
const rd = DATASETS[0];
both(rd, 255);
run(scalar, 255, 0, 1, 100_000); /* warm up both code paths */
run(simd, 255, 0, 1, 100_000);

/* Interleave the two so a burst of machine load hits both kinds of run, and
 * take each one's fastest round: the wall clock on a shared box is noisy, the
 * best time is the closest thing to the kernel's own cost. */
let scalarMs = Infinity;
let simdMs = Infinity;
for (let round = 0; round < ROUNDS; round++) {
  let t = performance.now();
  run(scalar, 255, 0, 1, N);
  scalarMs = Math.min(scalarMs, performance.now() - t);

  t = performance.now();
  run(simd, 255, 0, 1, N);
  simdMs = Math.min(simdMs, performance.now() - t);
}

const scalarRate = N / (scalarMs / 1000);
const simdRate = N / (simdMs / 1000);

console.log(`rate: scalar ${(scalarRate / 1e6).toFixed(2)} MHash/s ` +
            `(${N} hashes in ${scalarMs.toFixed(0)} ms)`);
console.log(`rate: simd   ${(simdRate / 1e6).toFixed(2)} MHash/s ` +
            `(${N} hashes in ${simdMs.toFixed(0)} ms)`);
console.log(`speedup: ${(simdRate / scalarRate).toFixed(2)}x`);
console.log(`meatrider-simd: ${checks} checks passed`);
