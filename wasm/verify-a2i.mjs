#!/usr/bin/env node
/**
 * verify-a2i.mjs — is the WAT fill_block bit-identical to the C reference?
 *
 * fill_vectors.txt is produced by compiling the vendored Argon2 reference itself
 * (ref_fill_vectors.c), so what this compares against is not another port. Each
 * block of the file is: "trial N xor M", then prev / ref / next (128 words each,
 * the inputs echoed so nothing has to be guessed), then result.
 *
 *   node wasm/verify-a2i.mjs
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DST = 4096, PREV = 4096 + 1024, REF = 4096 + 2048;

const lines = readFileSync(join(HERE, 'fill_vectors.txt'), 'utf8').trim().split('\n');
const trials = [];
let i = 0;
while (i < lines.length) {
  const header = /^trial (\d+) xor (\d+)$/.exec(lines[i++].trim());
  if (!header) throw new Error(`bad header at line ${i}: ${lines[i - 1]}`);
  const read = (name) => {
    if (lines[i++].trim() !== name) throw new Error(`expected ${name} at line ${i}`);
    const words = [];
    while (words.length < 128) words.push(...lines[i++].trim().split(/\s+/));
    return words;
  };
  trials.push({
    trial: Number(header[1]), withXor: Number(header[2]),
    prev: read('prev'), ref: read('ref'), next: read('next'), result: read('result'),
  });
}

const { instance } = await WebAssembly.instantiate(readFileSync(join(HERE, 'argon2_fill.wasm')), {});
const ex = instance.exports;
const dv = new DataView(ex.memory.buffer);
const write = (addr, words) =>
  words.forEach((w, k) => dv.setBigUint64(addr + 8 * k, BigInt('0x' + w), true));
const read = (addr) =>
  Array.from({ length: 128 }, (_, k) => dv.getBigUint64(addr + 8 * k, true).toString(16).padStart(16, '0'));

let failures = 0;
for (const t of trials) {
  write(PREV, t.prev);
  write(REF, t.ref);
  write(DST, t.next);                       // the initial "next block" contents
  ex.fill_block(DST, PREV, REF, t.withXor);

  const got = read(DST);
  const bad = [];
  for (let k = 0; k < 128; k++) if (got[k] !== t.result[k]) bad.push(k);

  const label = `trial ${t.trial} (with_xor=${t.withXor})`;
  if (bad.length === 0) {
    console.log(`  ok   ${label}: 128/128 words identical to the C reference`);
  } else {
    failures++;
    console.log(`  FAIL ${label}: ${bad.length} word(s) differ, first at ${bad[0]} ` +
                `(got ${got[bad[0]]}, want ${t.result[bad[0]]})`);
  }
}

console.log(`\n${failures === 0 ? 'fill_block matches the C reference bit for bit' : failures + ' trial(s) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
