#!/usr/bin/env node
// test-webgpu.js — check the extension's WebGPU nonce placement without a GPU.
//
// The shader never builds the message itself: the host pads it once with the
// four nonce bytes left zero and passes shifts and masks (wpA/wpB/keepA/
// shiftA/keepB/shiftB/swap) that drop the nonce in. That arithmetic is the part
// most likely to be wrong, and it can be checked exactly against node's crypto
// on the CPU: apply the same masks to the same words, hash, compare.
//
//   node firefox-extension/test-webgpu.js
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { template, message, digestHex } = require(join(here, "webgpu/gpu-solver.js"));

let checks = 0;
let fails = 0;
function check(what, ok, detail) {
  checks++;
  if (!ok) fails++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}${ok || !detail ? "" : ` — ${detail}`}`);
}

const sha256 = (u8) => createHash("sha256").update(Buffer.from(u8)).digest();
const be32 = (w) => [(w >>> 24) & 255, (w >>> 16) & 255, (w >>> 8) & 255, w & 255];

/** What the shader computes: template words with the nonce inserted. */
function shaderMessage(tpl, nonce) {
  const words = Array.from(tpl.words);
  const n = nonce >>> 0;
  // the shader byte-swaps V for the little-endian encoding (`swap`)
  const v = tpl.swap ? (((n & 255) << 24) | (((n >>> 8) & 255) << 16) | (((n >>> 16) & 255) << 8) | ((n >>> 24) & 255)) >>> 0 : n;
  words[tpl.wpA] = ((words[tpl.wpA] & tpl.keepA) | (v >>> tpl.shiftA)) >>> 0;
  if (tpl.wpB !== 0xffffffff) {
    words[tpl.wpB] = ((words[tpl.wpB] & tpl.keepB) | (v << tpl.shiftB)) >>> 0;
  }
  const out = new Uint8Array(words.length * 4);
  words.forEach((w, i) => out.set(be32(w), i * 4));
  // The padded block already carries the 0x80 and the bit length, so only the
  // message bytes are hashed: hashing the whole block would pad it twice.
  return out.slice(0, tpl.len + 4);
}

// A real Anubis randomData is 32 bytes of hex; the other lengths exercise the
// word-remainder branches (r = len & 3) and the big/little endian switch.
const CH = "6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d";
const CH_LE = CH.slice(0, -2) + "fd";
const cases = [
  ["32 bytes, nonce big-endian", CH, [0, 1, 12345, 0xdeadbeef]],
  ["32 bytes, nonce little-endian", CH_LE, [0, 1, 12345, 0xdeadbeef]],
  ["30 bytes (r=2)", CH.slice(0, 60), [0, 7, 0xffffffff]],
  ["33 bytes (r=1)", CH + "ab", [0, 3, 0x12345678]],
  ["28 bytes (r=0)", CH.slice(0, 56), [0, 5, 0xcafebabe]],
];

console.log("shader nonce placement vs node crypto");
for (const [label, chal, nonces] of cases) {
  const tpl = template(chal);
  for (const nonce of nonces) {
    const want = sha256(message(chal, nonce));
    const got = sha256(shaderMessage(tpl, nonce));
    check(`${label} nonce ${nonce}`, digestHex([]) === "" && Buffer.compare(Buffer.from(got), Buffer.from(want)) === 0,
      `gpu-math ${got.toString("hex").slice(0, 16)} reference ${want.toString("hex").slice(0, 16)}`);
  }
}

// The endianness switch itself: the same challenge with the last byte flipped
// must produce different bytes for the same nonce.
{
  const a = message(CH, 1);
  const b = message(CH_LE, 1);
  check("both byte orders are exercised", Buffer.compare(Buffer.from(a), Buffer.from(b)) !== 0);
  check("big-endian puts the nonce last", Buffer.from(a.slice(-4)).equals(Buffer.from([0, 0, 0, 1])));
  check("little-endian puts it reversed", Buffer.from(b.slice(-4)).equals(Buffer.from([1, 0, 0, 0])));
}

// The shader's block count: the padding has to fit the length field.
for (const chal of [CH, CH.slice(0, 60), CH + "ab"]) {
  const tpl = template(chal);
  check(`padded block count for ${chal.length / 2} bytes`, tpl.blocks === Math.ceil((chal.length / 2 + 4 + 9) / 64));
}

// Constants shared with the shader: a drift here silently drops work.
const wgsl = readFileSync(join(here, "webgpu/sha256.wgsl"), "utf8");
const size = /@workgroup_size\((\d+)\)/.exec(wgsl);
check("wgsl @workgroup_size is 64", size && size[1] === "64", size?.[1]);
check("wgsl runs four nonces per invocation (vec4 lanes)", /vec4<u32>/.test(wgsl));

console.log(`\n${checks - fails}/${checks} checks passed`);
process.exit(fails ? 1 : 0);
