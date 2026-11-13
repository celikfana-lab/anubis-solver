#!/usr/bin/env node
/**
 * verify-hashx-module.mjs — does our HashX module agree with the one Anubis ships?
 *
 * Same shape as verify-a2i-module.mjs: both modules get the same challenge and
 * nonce, and the official module is asked to accept our answer with its own
 * `anubis_validate`. That is a stronger statement than "the digest changed when
 * we rebuilt", which is what a size change in the module looks like from the
 * outside.
 *
 *   node wasm/verify-hashx-module.mjs [our-module.wasm]
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OFFICIAL =
  process.env.ANUBIS_WASM_DIR ??
  join(HERE, '../../anubis/web/static/wasm/simd128/hashx.wasm');

const ourPath = resolve(process.argv[2] ?? join(HERE, 'hashx_pow.wasm'));
for (const [label, p] of [['ours', ourPath], ['official', OFFICIAL]]) {
  if (!existsSync(p)) {
    console.error(`no ${label} module at ${p}`);
    process.exit(2);
  }
}

const official = new WebAssembly.Instance(
  new WebAssembly.Module(readFileSync(OFFICIAL)),
  { anubis: { anubis_update_nonce: () => {} } },
).exports;
const ours = new WebAssembly.Instance(
  new WebAssembly.Module(readFileSync(ourPath)), {},
).exports;

function answer(challenge, difficulty, base) {
  new Uint8Array(ours.memory.buffer).set(challenge, ours.data_ptr());
  ours.set_data_length(challenge.length);
  const nonce = ours.anubis_work(difficulty, base, 1) >>> 0;
  const digest = Buffer.from(new Uint8Array(
    ours.memory.buffer, ours.result_hash_ptr(), ours.result_hash_size(),
  )).toString('hex');
  return { nonce, digest };
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

/* hashx is cheap per hash (microseconds), so the difficulty can be honest here */
const DIFFICULTIES = [4, 8, 12, 16];
let seed = 0xabcdef01;
const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed; };

let failures = 0;
const total = 8;
for (let c = 0; c < total; c++) {
  const challenge = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) challenge[i] = (rnd() >>> 8) & 0xff;
  const difficulty = DIFFICULTIES[c % DIFFICULTIES.length];
  const a = answer(challenge, difficulty, 500 + c * 11);
  const ok = officialAccepts(challenge, difficulty, a);
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} c=${c} difficulty=${difficulty} ` +
              `nonce=${a.nonce} digest=${a.digest.slice(0, 16)}...`);
}
console.log(`\n${total - failures}/${total} challenges agree with the official Anubis module`);
process.exit(failures ? 1 : 0);
