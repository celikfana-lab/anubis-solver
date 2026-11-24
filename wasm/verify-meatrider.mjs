#!/usr/bin/env node
/**
 * verify-meatrider.mjs -- does the wasm kernel compute the Bitcoin header we
 * documented?
 *
 * There is no official Anubis module for this tier, so the independent
 * implementation is Node's own SHA-256 (OpenSSL, via node:crypto) with the
 * header assembled here from the specification in src/meatrider/meatrider.h.
 * That is a real second implementation: a mistake in the module's C would have
 * to be repeated in this file's assembly of the header to go unnoticed.
 *
 *   node wasm/verify-meatrider.mjs [module.wasm]
 */
import { readFileSync, existsSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ourPath = resolve(process.argv[2] ?? join(HERE, 'meatrider_pow.wasm'));
if (!existsSync(ourPath)) {
  console.error(`no module at ${ourPath}`);
  process.exit(2);
}

const VERSION = 1;
const TIME = 1231006505;

const ex = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(ourPath)), {}).exports;

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
  buf.writeUInt32LE(nonce, 76);
  return buf;
}

/* SHA-256d, reversed: Bitcoin's display order. */
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

function work(rd, difficulty, base, limit) {
  const mem = new Uint8Array(ex.memory.buffer);
  mem.set(rd, ex.data_ptr());
  ex.set_data_length(rd.length);
  const nonce = ex.anubis_work_limited(difficulty, base, 1, limit);
  const got = Buffer.from(new Uint8Array(ex.memory.buffer, ex.result_hash_ptr(), ex.result_hash_size()));
  return { nonce, digest: got.toString('hex') };
}

let checks = 0;
function eq(label, a, b) {
  checks++;
  if (a !== b) {
    console.error(`FAIL ${label}\n  got  ${a}\n  want ${b}`);
    process.exit(1);
  }
}

/* 1. the documented construction, against the kernel's own answer */
for (const difficulty of [1, 2, 3, 5, 8, 11, 12]) {
  for (let round = 0; round < 3; round++) {
    const rd = randomBytes(32);
    const { nonce, digest: got } = work(rd, difficulty, 0, 1 << 24);
    if (nonce < 0) {
      console.error(`FAIL no nonce at difficulty ${difficulty}`);
      process.exit(1);
    }
    eq(`digest d=${difficulty} nonce=${nonce}`, got, bitcoinHash(rd, difficulty, nonce).toString('hex'));
    eq(`leading bits d=${difficulty} nonce=${nonce}`,
       lz(Buffer.from(got, 'hex')) >= difficulty, true);
    /* and the header really is 80 bytes with the fields where we said */
    const h = header(rd, difficulty, nonce);
    eq(`header length`, h.length, 80);
    eq(`header version`, h.readUInt32LE(0), VERSION);
    eq(`header time`, h.readUInt32LE(68), TIME);
    eq(`header bits`, h.readUInt32LE(72), compact(1n << BigInt(256 - difficulty)));
    eq(`header nonce`, h.readUInt32LE(76), nonce);
    eq(`header prev`, h.subarray(4, 36).toString('hex'), rd.toString('hex'));
  }
}

/* 2. nBits round-trips for every difficulty the tier accepts */
function targetFromCompact(bits) {
  const exp = bits >>> 24;
  const mant = bits & 0x007fffff;
  return exp <= 3 ? BigInt(mant) >> BigInt(8 * (3 - exp))
                  : BigInt(mant) << BigInt(8 * (exp - 3));
}
for (let d = 1; d <= 255; d++) {
  const bits = compact(1n << BigInt(256 - d));
  eq(`compact round-trip d=${d}`, targetFromCompact(bits), 1n << BigInt(256 - d));
}

/* 3. the limited window really is limited: a hard difficulty must return -1 */
const hard = work(randomBytes(32), 30, 0, 16);
eq('limited window exhausts', hard.nonce, -1);

/* 4. a window that starts late still finds the same answer as a full scan */
{
  const rd = randomBytes(32);
  const { nonce } = work(rd, 6, 0, 1 << 20);
  const from = Math.max(0, nonce - 2);
  const again = work(rd, 6, from, 8);
  eq('late window finds the neighbour', again.nonce >= 0, true);
  eq('late window digest', again.digest, bitcoinHash(rd, 6, again.nonce).toString('hex'));
}

/* 5. a real rate, so the number in the docs has a command behind it */
{
  const rd = randomBytes(32);
  const N = 4_000_000;
  const t0 = performance.now();
  work(rd, 255, 0, N); /* impossible difficulty: the window runs to the end */
  const ms = performance.now() - t0;
  console.log(`rate: ${(N / (ms / 1000) / 1e6).toFixed(2)} MHash/s ` +
              `(${N} hashes in ${ms.toFixed(0)} ms)`);
}

console.log(`meatrider: ${checks} checks passed`);
