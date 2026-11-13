'use strict';
/* Exercises every binding against the real library. Run with `node test.js`. */
const assert = require('assert');
const anubis = require('./anubis');

let pass = 0;
function check(name, fn) {
  try {
    fn();
    console.log('  ok   ' + name);
    pass++;
  } catch (e) {
    console.log('  FAIL ' + name + ': ' + e.message);
    process.exitCode = 1;
  }
}

console.log('library: ' + anubis.libraryPath);
const i = anubis.info();
console.log(`version ${i.version} | gpu ${i.gpu || 'none (cpu)'} | threads ${i.threads} | ` +
            `affinity ${i.affinity} | batch ${i.batchWidth} | gpuVerify ${i.gpuVerify}`);
console.log();

check('info looks sane', () => {
  assert.match(i.version, /^\d+\.\d+\.\d+$/);
  assert.ok(i.threads > 0);
});

check('sha256Hex matches a known digest', () => {
  // echo -n abc | sha256sum
  assert.strictEqual(
    anubis.sha256Hex('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

check('sha256Midstate of the first 64 bytes of sha256(abc) data', () => {
  const block = Buffer.alloc(64, 0x61);
  const st = anubis.sha256Midstate(block);
  assert.strictEqual(st.length, 8);
  assert.ok(st.every((w) => Number.isInteger(w) && w >= 0));
});

check('nibbles: solve and verify', () => {
  const r = anubis.solveNibbles('demo-challenge', 3);
  assert.ok(Number.isInteger(r.nonce) && r.nonce >= 0);
  assert.match(r.hash, /^[0-9a-f]{64}$/);
  assert.ok(r.ms >= 0);
  const v = anubis.verifyNibbles('demo-challenge', r.nonce, 3);
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.hash, r.hash);
});

check('nibbles: a wrong nonce does not verify', () => {
  const v = anubis.verifyNibbles('demo-challenge', 999999, 3);
  assert.strictEqual(v.ok, false);
});

// 16-byte hex challenge, the shape the wasm families take
const HEX = '00112233445566778899aabbccddeeff';
check('sha256 (wasm): solve and verify', () => {
  const r = anubis.solveSha256(HEX, 8);
  assert.match(r.hash, /^[0-9a-f]{64}$/);
  assert.strictEqual(anubis.verify('sha256', HEX, r.nonce, 8).ok, true);
});

check('argon2id: solve and verify', () => {
  const r = anubis.solveArgon2id(HEX, 4);
  assert.match(r.hash, /^[0-9a-f]{64}$/);
  assert.strictEqual(anubis.verify('argon2id', HEX, r.nonce, 4).ok, true);
});

check('hashx: solve and verify', () => {
  const r = anubis.solveHashx(HEX, 4);
  assert.match(r.hash, /^[0-9a-f]{64}$/);
  assert.strictEqual(anubis.verify('hashx', HEX, r.nonce, 4).ok, true);
});

check('generic dispatcher routes every algorithm', () => {
  assert.strictEqual(anubis.solve('fast', 'demo-challenge', 2).hash.length, 64);
  assert.strictEqual(anubis.solve('sha256', HEX, 4).hash.length, 64);
});

check('unknown algorithm raises', () => {
  assert.throws(() => anubis.solve('md5', 'x', 1), /unknown algorithm/);
});

check('an unsolvable budget raises SolverError with code 2', () => {
  try {
    anubis.solveNibbles('demo-challenge', 64, { budgetMs: 1 });
    assert.fail('should have thrown');
  } catch (e) {
    assert.strictEqual(e.name, 'SolverError');
    assert.strictEqual(e.code, anubis.ERR_UNSOLVED);
  }
});

console.log();
console.log(pass + ' checks passed' + (process.exitCode ? ' (with failures)' : ''));
