#!/usr/bin/env node
/**
 * verify-a2i-module.mjs — does our Argon2id module agree with the one Anubis ships?
 *
 * The fill-vector test (verify-a2i.mjs) checks the block function in isolation.
 * This checks the whole thing: the driver, the salt encoding, the endianness
 * choice, the difficulty test and the search loop. Both modules are handed the
 * same challenge and nonce, and the official module is then asked to validate
 * our answer with its own `anubis_validate`, so agreement is not just "we match
 * our own previous binary".
 *
 * Why this exists: argon2id_pow.wasm once shipped built with -ffreestanding,
 * which turned every 1 KiB block copy into a byte-at-a-time memcpy call and made
 * the module 2.0x slower than it should have been. Nothing noticed, because
 * nothing compared the module against anything outside this repo. This does.
 *
 *   node wasm/verify-a2i-module.mjs [our-module.wasm]
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OFFICIAL =
  process.env.ANUBIS_WASM_DIR ??
  join(HERE, '../../anubis/web/static/wasm/simd128/argon2id.wasm');

const ourPath = resolve(process.argv[2] ?? join(HERE, 'argon2id_pow.wasm'));
if (!existsSync(ourPath)) {
  console.error(`no module at ${ourPath}; run make in wasm/ first`);
  process.exit(2);
}
if (!existsSync(OFFICIAL)) {
  console.error(`no official module at ${OFFICIAL}; set ANUBIS_WASM_DIR`);
  process.exit(2);
}

const official = new WebAssembly.Instance(
  new WebAssembly.Module(readFileSync(OFFICIAL)),
  { anubis: { anubis_update_nonce: () => {} } },
).exports;
const ours = new WebAssembly.Instance(
  new WebAssembly.Module(readFileSync(ourPath)),
  {},
).exports;

const hex = (b) => Buffer.from(b).toString('hex');

function ourAnswer(challenge, difficulty, base) {
  new Uint8Array(ours.memory.buffer).set(challenge, ours.data_ptr());
  ours.set_data_length(challenge.length);
  const nonce = ours.anubis_work(difficulty, base, 1) >>> 0;
  const digest = new Uint8Array(
    ours.memory.buffer, ours.result_hash_ptr(), ours.result_hash_size(),
  );
  return { nonce, digest: hex(digest) };
}

function officialAccepts(challenge, difficulty, { nonce, digest }) {
  new Uint8Array(official.memory.buffer).set(challenge, official.data_ptr());
  official.set_data_length(challenge.length);
  new Uint8Array(
    official.memory.buffer,
    official.verification_hash_ptr(),
    official.verification_hash_size(),
  ).set(Buffer.from(digest, 'hex'));
  return official.anubis_validate(nonce, difficulty);
}

/* difficulties stay small on purpose: argon2id is 19 MiB of memory-hard work per
 * hash, so difficulty 5 is already ~32 hashes and difficulty 20 would never
 * finish inside a test */
const DIFFICULTIES = [1, 2, 3, 4, 5];
let seed = 0x12345678;
const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed; };

let failures = 0;
const total = 10;
for (let c = 0; c < total; c++) {
  const challenge = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) challenge[i] = (rnd() >>> 8) & 0xff;
  const difficulty = DIFFICULTIES[c % DIFFICULTIES.length];
  const answer = ourAnswer(challenge, difficulty, 1000 + c * 37);
  const ok = officialAccepts(challenge, difficulty, answer);
  if (!ok) {
    failures++;
    console.log(`FAIL c=${c} difficulty=${difficulty} nonce=${answer.nonce} ` +
                `digest=${answer.digest}`);
  } else {
    console.log(`ok   c=${c} difficulty=${difficulty} nonce=${answer.nonce} ` +
                `digest=${answer.digest.slice(0, 16)}...`);
  }
}

console.log(`\n${total - failures}/${total} challenges agree with the official Anubis module`);
process.exit(failures ? 1 : 0);
