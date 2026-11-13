#!/usr/bin/env node
/**
 * verify-jit.mjs - does the runtime-built HashX module behave like the interpreter?
 *
 * hashx_jit.mjs derives a HashX program from an arbitrary 32-byte challenge and
 * emits a specialized wasm module. hashx_pow.wasm is the independent reference:
 * the C interpreter, same derivation, same ABI. If they disagree on any digest,
 * the emitter is wrong. The committed vector also pins the JS generator to the
 * C generator that produced beyond/vectors/hx_vectors.hex.
 *
 * Then the benchmark: warm, counted hashes, one process, so the runtime-built
 * module, our interpreter and the official module are measured the same way.
 *
 *   node wasm/verify-jit.mjs
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { deriveProgram, buildModule } from './hashx_jit.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const NONCES = 64;
const SOLVE_DIFFICULTIES = [8, 12, 16];
const BENCH_DIFFICULTY = 20;

// app.js is the browser demo and owns the committed vector; read it rather than
// copying the constants, so a change there shows up here.
const app = readFileSync(join(HERE, 'demo', 'app.js'), 'utf8');
const CHALLENGE_HEX = /CHALLENGE_HEX = '([0-9a-f]+)'/.exec(app)[1];
const EXPECTED_DIGEST = /EXPECTED_DIGEST = '([^']+)'/.exec(app)[1];

// Found by searching random 32-byte challenges with deriveProgram(): the
// generator rejects this seed and Anubis's module retries with a counter
// appended. Pinning one makes the retry path a check instead of a 47 s search.
const RETRY_CHALLENGE_HEX = 'a7ed4227f9e71d442321c59a94d4724c5c23b74cbb273a4743dea358c1e0890b';

const words = (bytes) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return [0, 1, 2, 3].map((i) => view.getBigUint64(8 * i, true).toString(16).padStart(16, '0')).join('|');
};

function leadingZeroBits(bytes) {
  let bits = 0;
  for (const b of bytes) {
    if (b === 0) { bits += 8; continue; }
    bits += Math.clz32(b) - 24;
    break;
  }
  return bits;
}

let failures = 0;
const check = (label, ok, detail = '') => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? '  ' + detail : ''}`);
  if (!ok) failures++;
};

const hexToBytes = (hex) => Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));

/* ------------------------------------------------------- the reference */

const powModule = new WebAssembly.Module(readFileSync(join(HERE, 'hashx_pow.wasm')));
const newPow = () => new WebAssembly.Instance(powModule, { anubis: { anubis_update_nonce: () => {} } });

function powDigest(ex) {
  const mem = new Uint8Array(ex.memory.buffer);
  return mem.slice(ex.result_hash_ptr(), ex.result_hash_ptr() + ex.result_hash_size());
}

function loadPow(ex, challenge) {
  new Uint8Array(ex.memory.buffer).set(challenge, ex.data_ptr());
  ex.set_data_length(challenge.length);
}

/* --------------------------------------------- generator against the vector */

{
  const vector = readFileSync(join(REPO, 'beyond', 'vectors', 'hx_vectors.hex'), 'utf8')
    .trim().split(/\s+/).map((x) => BigInt('0x' + x));
  const keys = vector.slice(0, 4);
  const derived = deriveProgram(hexToBytes(CHALLENGE_HEX));

  const keyOk = derived.registerKey.every((k, i) => k === keys[i]);
  check('committed vector: BLAKE2b/SipHash keys match the C generator', keyOk,
    derived.registerKey.map((k) => '0x' + k.toString(16)).join(' '));

  let bad = 0;
  for (let i = 0; i < 512; i++) {
    const want = vector.slice(6 + 4 * i, 6 + 4 * i + 4).map(Number);
    const got = [derived.program[i].op, derived.program[i].dst >>> 0,
                 derived.program[i].src >>> 0, derived.program[i].imm >>> 0];
    if (want[0] !== got[0] || want[1] !== got[1] || want[2] !== got[2] || want[3] !== got[3]) bad++;
  }
  check('committed vector: all 512 generated instructions match', bad === 0,
    bad ? `${bad} differ` : '512/512');
  check('committed vector: no seed retry needed', derived.counter === 0);
  check('committed vector: nInstruction export is 512',
    new WebAssembly.Instance(new WebAssembly.Module(buildModule(hexToBytes(CHALLENGE_HEX))), {})
      .exports.ninstr() === 512);
}

/* --------------------------------------- the emitter against its own demo vector */

{
  const challenge = hexToBytes(CHALLENGE_HEX);
  const ex = new WebAssembly.Instance(new WebAssembly.Module(buildModule(challenge)), {}).exports;
  const lz = Number(ex.hash(0n));
  const digest = new Uint8Array(ex.memory.buffer, 0, 32).slice();
  check('emitted module: digest(nonce 0) is demo/app.js EXPECTED_DIGEST',
    words(digest) === EXPECTED_DIGEST, words(digest));
  check('emitted module: hash() returns the digest leading zero bits',
    lz === leadingZeroBits(digest), `${lz} bits`);
  check('emitted module: result_hash_ptr/result_hash_size describe that digest',
    ex.result_hash_ptr() === 0 && ex.result_hash_size() === 32);
  const alias = Number(ex.digest(0n));
  check('emitted module: digest() is the hash() alias', alias === lz && ex.memory !== undefined);
}

/* ------------------------- the committed module agrees with the runtime-built one */

{
  const committed = new WebAssembly.Instance(
    new WebAssembly.Module(readFileSync(join(HERE, 'hashx_jit.wasm'))), {}).exports;
  const challenge = hexToBytes(CHALLENGE_HEX);
  const built = new WebAssembly.Instance(new WebAssembly.Module(buildModule(challenge)), {}).exports;

  let same = true;
  for (let n = 0; n < NONCES; n++) {
    committed.hash(BigInt(n));
    const a = new Uint8Array(committed.memory.buffer, 0, 32).slice();
    built.hash(BigInt(n));
    const b = new Uint8Array(built.memory.buffer, 0, 32).slice();
    if (!a.every((v, i) => v === b[i])) { same = false; break; }
  }
  check(`committed hashx_jit.wasm agrees on digests for ${NONCES} nonces`, same);

  const a = Number(committed.solve(0n, 16n, 1n << 24n));
  const b = Number(built.solve(0n, 16n, 1n << 24n));
  check('committed hashx_jit.wasm agrees on the difficulty 16 nonce', a === b, `${a} / ${b}`);
}

/* ----------------------------- arbitrary challenges, against the interpreter */

function compareChallenge(label, challenge) {
  const derived = deriveProgram(challenge);
  const ex = new WebAssembly.Instance(new WebAssembly.Module(buildModule(challenge)), {}).exports;
  const ref = newPow().exports;
  loadPow(ref, challenge);

  let bad = 0;
  let firstBad = '';
  for (let n = 0; n < NONCES; n++) {
    const returned = ref.anubis_work(0, n, 1) >>> 0; // difficulty 0: one hash, returns the nonce
    const expected = powDigest(ref);
    const bits = Number(ex.hash(BigInt(n)));
    const digest = new Uint8Array(ex.memory.buffer, 0, 32).slice();
    if (returned !== n || bits !== leadingZeroBits(digest) || !expected.every((v, i) => v === digest[i])) {
      bad++;
      if (!firstBad) firstBad = `nonce ${n}`;
    }
  }
  check(`${label}: ${NONCES} nonces agree on digest and leading zero bits`, bad === 0,
    bad ? `${bad} bad (${firstBad})` : 'digest equal');

  for (const difficulty of SOLVE_DIFFICULTIES) {
    const refNonce = ref.anubis_work(difficulty, 0, 1) >>> 0;
    const refDigest = powDigest(ref);
    const nonce = Number(ex.solve(0n, BigInt(difficulty), 1n << 24n));
    const digest = new Uint8Array(ex.memory.buffer, 0, 32).slice();
    const ok = nonce === refNonce && leadingZeroBits(digest) >= difficulty &&
               digest.every((v, i) => v === refDigest[i]);
    check(`${label}: difficulty ${difficulty} solve agrees`, ok, `nonce ${nonce}`);
  }

  // the page calls anubis_work with an iterand and an arbitrary start nonce
  const refNonce2 = ref.anubis_work(12, 1000, 2) >>> 0;
  const refDigest2 = powDigest(ref);
  const nonce2 = ex.anubis_work(12, 1000, 2) >>> 0;
  const digest2 = new Uint8Array(ex.memory.buffer, 0, 32).slice();
  check(`${label}: anubis_work(nonce 1000, iterand 2) agrees`,
    nonce2 === refNonce2 && digest2.every((v, i) => v === refDigest2[i]),
    `nonce ${nonce2}`);

  return derived.counter;
}

const randomChallenges = Array.from({ length: 8 }, () => randomBytes(32));
for (let i = 0; i < randomChallenges.length; i++) {
  compareChallenge(`random challenge ${i + 1}`, randomChallenges[i]);
}
const retryCounter = compareChallenge('seed retry challenge', hexToBytes(RETRY_CHALLENGE_HEX));
check('seed retry challenge actually needed the retry path', retryCounter > 0, `counter ${retryCounter}`);
// Anubis normally sends 32 bytes, but the derivation accepts any length and the
// BLAKE2b update has a different path once the seed crosses one 128-byte block.
compareChallenge('long challenge (200 bytes)', randomBytes(200));

/* ------------------- the emitter inlined in betterAnusbis matches this module */

{
  const source = readFileSync(join(REPO, 'betterAnusbis', 'betterAnusbis.c'), 'utf8');
  const begin = source.indexOf('/* HASHX-JIT-BEGIN */');
  const end = source.indexOf('/* HASHX-JIT-END */');
  if (begin < 0 || end < 0) {
    check('betterAnusbis.c carries an inline copy of the emitter', false, 'markers not found');
  } else {
    const block = source.slice(begin, end).replace('/* HASHX-JIT-BEGIN */', '');
    let inline;
    try {
      inline = new Function(block + '\nreturn HASHX_JIT;')();
    } catch (err) {
      check('the inline emitter parses as JavaScript', false, String(err));
    }
    if (inline) {
      let same = true;
      for (const challenge of [hexToBytes(CHALLENGE_HEX), randomChallenges[0]]) {
        const a = buildModule(challenge);
        const b = inline.buildModule(challenge);
        if (a.length !== b.length || !a.every((v, i) => v === b[i])) same = false;
      }
      check('inline emitter emits byte-identical modules', same);
    }
  }
}

/* ---------------------------------------------------------------- benchmark */

function benchOfficial(label, path, challenge) {
  const file = join(HERE, 'demo', path);
  if (!existsSync(file)) {
    console.log(`  skip official ${label}: ${file} not present`);
    return null;
  }
  const module = new WebAssembly.Module(readFileSync(file));
  const make = () => new WebAssembly.Instance(module, {
    anubis: { anubis_update_nonce: () => {} },
  }).exports;
  const ex = make();
  loadPow(ex, challenge);
  ex.anubis_work(16, 0, 1); // warm past the wasm baseline compiler's tier-up

  let best = null;
  for (let run = 0; run < 2; run++) {
    const t0 = performance.now();
    const nonce = ex.anubis_work(BENCH_DIFFICULTY, 0, 1) >>> 0;
    const seconds = (performance.now() - t0) / 1000;
    const digest = powDigest(ex);
    const rate = (nonce + 1) / seconds;
    if (!best || rate > best.rate) best = { name: label, rate, nonce, seconds, digest };
  }
  return best;
}

{
  const challenge = hexToBytes(CHALLENGE_HEX);
  const results = [];

  const jitBytes = buildModule(challenge);
  const jit = new WebAssembly.Instance(new WebAssembly.Module(jitBytes), {}).exports;
  jit.solve(0n, 16n, 1n << 24n); // warm past the wasm baseline compiler's tier-up
  let best = null;
  for (let run = 0; run < 2; run++) {
    const t0 = performance.now();
    const nonce = Number(jit.solve(0n, BigInt(BENCH_DIFFICULTY), 1n << 26n));
    const seconds = (performance.now() - t0) / 1000;
    const digest = new Uint8Array(jit.memory.buffer, 0, 32).slice();
    const rate = (nonce + 1) / seconds;
    if (!best || rate > best.rate) best = { name: 'runtime-built module', rate, nonce, seconds, digest, bytes: jitBytes.length };
  }
  results.push(best);

  const ref = newPow().exports;
  loadPow(ref, challenge);
  ref.anubis_work(16, 0, 1); // warm
  best = null;
  for (let run = 0; run < 2; run++) {
    const t0 = performance.now();
    const nonce = ref.anubis_work(BENCH_DIFFICULTY, 0, 1) >>> 0;
    const seconds = (performance.now() - t0) / 1000;
    const digest = powDigest(ref);
    const rate = (nonce + 1) / seconds;
    if (!best || rate > best.rate) best = { name: 'hashx_pow.wasm (interpreter)', rate, nonce, seconds, digest };
  }
  results.push(best);

  for (const [label, file] of [['official baseline', 'official/hashx-baseline.wasm'],
                               ['official simd128', 'official/hashx-simd128.wasm']]) {
    const r = benchOfficial(label, file, challenge);
    if (r) results.push(r);
  }

  // all of them solved the same challenge at the same difficulty: same first hit
  const nonce = results[0].nonce;
  const digest = words(results[0].digest);
  const agreed = results.every((r) => r.nonce === nonce && words(r.digest) === digest);

  console.log(`\nbenchmark: difficulty ${BENCH_DIFFICULTY}, ${nonce + 1} counted hashes, warm, best of 2`);
  console.log(`  ${'module'.padEnd(30)} ${'hashes/s'.padStart(12)}  ${'per hash'.padStart(9)}  size`);
  for (const r of results) {
    console.log(`  ${r.name.padEnd(30)} ${Math.round(r.rate).toLocaleString('en-US').padStart(12)}` +
                `  ${((r.seconds * 1e6) / (r.nonce + 1)).toFixed(3).padStart(7)} us` +
                `  ${r.bytes ? r.bytes + ' B' : '-'}`);
  }
  check('benchmark: every module found the same nonce and digest', agreed,
    agreed ? `nonce ${nonce}, ${digest}` : 'they disagree');
}

console.log(`\n${failures === 0 ? 'all checks passed' : failures + ' check(s) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
