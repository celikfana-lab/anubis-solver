'use strict';
/**
 * Node bindings for libanubis_solver — solve Anubis proof-of-work challenges.
 *
 *   const anubis = require('./anubis');
 *   const r = anubis.solveNibbles('demo-challenge', 3);
 *   console.log(r.nonce, r.hash, r.ms);
 *
 * The shared library is loaded with koffi (FFI), so there is no build step and
 * no native addon: point ANUBIS_LIB at the .so if it is not in the repo root.
 */
const fs = require('fs');
const path = require('path');

let koffi;
try {
  koffi = require('koffi');
} catch (e) {
  throw new Error(
    "the 'koffi' package is required: run `npm install` in bindings/node (or `npm i koffi`)"
  );
}

/* ---------------------------------------------------------------- library */

const CANDIDATES = [
  process.env.ANUBIS_LIB,
  path.join(__dirname, '..', '..', 'libanubis_solver.so'),
  path.join(__dirname, '..', '..', 'libanubis_solver.dylib'),
  path.join(process.cwd(), 'libanubis_solver.so'),
].filter(Boolean);

function findLibrary() {
  for (const p of CANDIDATES) {
    if (p && fs.existsSync(p)) return p;
  }
  throw new Error(
    'libanubis_solver not found. Build it with `make`, or set ANUBIS_LIB to its path.\n' +
      'looked in:\n  ' + CANDIDATES.join('\n  ')
  );
}

const lib = koffi.load(findLibrary());

/* Return codes from anubis-solver.h */
const OK = 0;
const ERR_ARG = 1;
const ERR_UNSOLVED = 2;
const ERR_INTERNAL = 3;

const RC_TEXT = {
  [ERR_ARG]: 'invalid argument',
  [ERR_UNSOLVED]: 'exhausted the nonce or time budget',
  [ERR_INTERNAL]: 'internal error',
};

class SolverError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'SolverError';
    this.code = code;
  }
}

/* ------------------------------------------------------------- signatures */

const f = {};

f.version = lib.func('const char *anubis_solver_version(void)');
f.gpuInfo = lib.func('const char *anubis_gpu_info(void)');
f.defaultThreads = lib.func('int anubis_default_threads(void)');
f.affinityInfo = lib.func('const char *anubis_cpu_affinity_info(void)');
f.batchWidth = lib.func('int anubis_batch_width(void)');
f.setGpuVerify = lib.func('void anubis_set_gpu_verify(int)');
f.gpuVerify = lib.func('int anubis_gpu_verify(void)');

f.sha256Hex = lib.func('int anubis_sha256_hex(const char *data, size_t len, void *out_hex)');
f.sha256Midstate = lib.func(
  'int anubis_sha256_midstate(const char *data, size_t len, _Out_ uint32_t *out)'
);

/* nibbles family: nonce is uint64 */
f.solveNibbles = lib.func('int anubis_solve_nibbles(const char *challenge, int difficulty, ' +
  'int threads, int64_t max_nonce, double budget_ms, _Out_ uint64_t *out_nonce, ' +
  'void *out_hex, _Out_ double *out_ms)');
f.verifyNibbles = lib.func('int anubis_verify_nibbles(const char *challenge, uint64_t nonce, ' +
  'int difficulty, void *out_hex)');

/* bits family: nonce is uint32 */
for (const [name, fn] of [
  ['Bits', 'anubis_solve_bits'],
  ['Argon2id', 'anubis_solve_argon2id'],
  ['Hashx', 'anubis_solve_hashx'],
]) {
  f['solve' + name] = lib.func(`int ${fn}(const char *challenge_hex, int difficulty, ` +
    'int threads, double budget_ms, _Out_ uint32_t *out_nonce, void *out_hex, ' +
    '_Out_ double *out_ms)');
  f['verify' + name] = lib.func(`int ${fn.replace('solve', 'verify')}` +
    '(const char *challenge_hex, uint32_t nonce, int difficulty, void *out_hex)');
}

/* ------------------------------------------------------------------ utils */

/* koffi NUL-terminates a JS string but NOT a Buffer, and every `const char *`
 * here is a C string - passing a Buffer makes hex_decode read past the end and
 * report ERR_ARG. Buffers are only correct where a length is passed as well
 * (anubis_sha256_hex / _midstate). */
function cstr(s) {
  return String(s);
}

/* koffi will not write back into a plain JS array or typed array for an
 * `_Out_` pointer, so every output scalar gets a real allocation. */
function outScalar(type, value) {
  const ptr = koffi.alloc(type, 1);
  if (value !== undefined) koffi.encode(ptr, type, value);
  return ptr;
}
function readScalar(ptr, type) {
  const v = koffi.decode(ptr, type);
  koffi.free(ptr);
  return v;
}

/* A Node Buffer passed to an out-pointer is not written back reliably - koffi
 * copies it - so out_hex is a real allocation too, decoded and freed after. */
function hexBuffer() {
  return koffi.alloc('uint8_t', 65);
}

function readHex(ptr) {
  const arr = Array.from(koffi.decode(ptr, 'uint8_t', 65));
  koffi.free(ptr);
  let end = arr.findIndex((v) => v === 0);
  if (end < 0) end = arr.length;
  return Buffer.from(arr.slice(0, end)).toString('latin1');
}

function throwRc(rc, what) {
  if (rc !== OK) {
    throw new SolverError(`${what}: ${RC_TEXT[rc] || 'code ' + rc}`, rc);
  }
}

/* -------------------------------------------------------------------- API */

/** Library and machine facts. */
function info() {
  return {
    version: f.version(),
    gpu: f.gpuInfo() || null,
    threads: f.defaultThreads(),
    affinity: f.affinityInfo() || null,
    batchWidth: f.batchWidth(),
    gpuVerify: f.gpuVerify() !== 0,
  };
}

function setGpuVerify(enable) {
  f.setGpuVerify(enable ? 1 : 0);
}

/** Hex SHA-256 of a string or Buffer. */
function sha256Hex(data) {
  const buf = Buffer.isBuffer(data) ? data : cstr(data);
  const out = hexBuffer();
  throwRc(f.sha256Hex(buf, buf.length, out), 'anubis_sha256_hex');
  return readHex(out);
}

/** SHA-256 midstate after `data` (length must be a multiple of 64). */
function sha256Midstate(data) {
  const buf = Buffer.isBuffer(data) ? data : cstr(data);
  if (buf.length % 64 !== 0) {
    throw new SolverError('midstate needs a multiple of 64 bytes', ERR_ARG);
  }
  const out = koffi.alloc('uint32_t', 8);
  throwRc(f.sha256Midstate(buf, buf.length, out), 'anubis_sha256_midstate');
  const words = Array.from(koffi.decode(out, 'uint32_t', 8));
  koffi.free(out);
  return words;
}

function threadsOrDefault(threads) {
  return threads === undefined || threads === null ? 0 : threads;
}

/**
 * `fast` / `slow`: SHA-256 over challenge || decimal nonce, leading zero nibbles.
 * @returns {{nonce: number, hash: string, ms: number}}
 */
function solveNibbles(challenge, difficulty, opts = {}) {
  const { threads = 0, maxNonce = -1, budgetMs = 0 } = opts;
  const nonce = outScalar('uint64_t');
  const out = hexBuffer();
  const ms = outScalar('double');
  const rc = f.solveNibbles(cstr(challenge), difficulty, threads,
    BigInt(maxNonce), budgetMs, nonce, out, ms);
  if (rc === ERR_UNSOLVED) {
    throw new SolverError('nibble search exhausted its budget', rc);
  }
  throwRc(rc, 'anubis_solve_nibbles');
  return { nonce: Number(readScalar(nonce, 'uint64_t')), hash: readHex(out),
           ms: readScalar(ms, 'double') };
}

/**
 * `sha256` (wasm): SHA-256 over raw challenge || uint32 nonce, leading zero bits.
 */
function solveSha256(challengeHex, difficulty, opts = {}) {
  return solveBitsFamily('solveBits', 'anubis_solve_bits', challengeHex, difficulty, opts);
}

function solveArgon2id(challengeHex, difficulty, opts = {}) {
  return solveBitsFamily('solveArgon2id', 'anubis_solve_argon2id', challengeHex, difficulty, opts);
}

function solveHashx(challengeHex, difficulty, opts = {}) {
  return solveBitsFamily('solveHashx', 'anubis_solve_hashx', challengeHex, difficulty, opts);
}

function solveBitsFamily(key, what, challengeHex, difficulty, opts) {
  const { threads = 0, budgetMs = 0 } = opts;
  const nonce = outScalar('uint32_t');
  const out = hexBuffer();
  const ms = outScalar('double');
  const rc = f[key](cstr(challengeHex), difficulty, threads, budgetMs, nonce, out, ms);
  if (rc === ERR_UNSOLVED) {
    throw new SolverError(`${what}: exhausted its budget`, rc);
  }
  throwRc(rc, what);
  return { nonce: readScalar(nonce, 'uint32_t'), hash: readHex(out),
           ms: readScalar(ms, 'double') };
}

function verifyNibbles(challenge, nonce, difficulty) {
  const out = hexBuffer();
  const rc = f.verifyNibbles(cstr(challenge), BigInt(nonce), difficulty, out);
  if (rc !== OK && rc !== ERR_UNSOLVED) throwRc(rc, 'anubis_verify_nibbles');
  return { ok: rc === OK, hash: readHex(out) };
}

function verifyBitsFamily(key, what, challengeHex, nonce, difficulty) {
  const out = hexBuffer();
  const rc = f[key](cstr(challengeHex), nonce, difficulty, out);
  if (rc !== OK && rc !== ERR_UNSOLVED) throwRc(rc, what);
  return { ok: rc === OK, hash: readHex(out) };
}

/* Generic dispatchers, matching the algorithm names Anubis uses. */
const ALGOS = {
  fast: { solve: solveNibbles, verify: verifyNibbles },
  slow: { solve: solveNibbles, verify: verifyNibbles },
  sha256: { solve: solveSha256, verify: (c, n, d) => verifyBitsFamily('verifyBits', 'anubis_verify_bits', c, n, d) },
  'wasm-sha256': { solve: solveSha256, verify: (c, n, d) => verifyBitsFamily('verifyBits', 'anubis_verify_bits', c, n, d) },
  argon2id: { solve: solveArgon2id, verify: (c, n, d) => verifyBitsFamily('verifyArgon2id', 'anubis_verify_argon2id', c, n, d) },
  hashx: { solve: solveHashx, verify: (c, n, d) => verifyBitsFamily('verifyHashx', 'anubis_verify_hashx', c, n, d) },
};

function solve(algorithm, challenge, difficulty, opts = {}) {
  const a = ALGOS[algorithm];
  if (!a) throw new SolverError(`unknown algorithm: ${algorithm}`, ERR_ARG);
  return a.solve(challenge, difficulty, opts);
}

function verify(algorithm, challenge, nonce, difficulty) {
  const a = ALGOS[algorithm];
  if (!a) throw new SolverError(`unknown algorithm: ${algorithm}`, ERR_ARG);
  return a.verify(challenge, nonce, difficulty);
}

module.exports = {
  info,
  setGpuVerify,
  sha256Hex,
  sha256Midstate,
  solve,
  solveNibbles,
  solveSha256,
  solveArgon2id,
  solveHashx,
  verify,
  verifyNibbles,
  SolverError,
  OK,
  ERR_ARG,
  ERR_UNSOLVED,
  ERR_INTERNAL,
  libraryPath: findLibrary(),
};
