// argon2id-blake2b.js — BLAKE2b-512, blake2b_long and Argon2id's host-side
// derivation (H0, B0, B1, the final tag), ported from the vendored reference:
//
//   third_party/argon2/blake2/blake2b.c      blake2b_init/update/final, blake2b_long
//   third_party/argon2/core.c                initial_hash(), fill_first_blocks(), finalize()
//   wasm/argon2id_pow.c                      the password/salt encoding Anubis uses
//
// The state is BigInt because this runs ~67 BLAKE2b compressions per Argon2id
// hash against 38,912 block fills on the GPU — it is noise either way, and
// BigInt is the version that is obviously right. See the comment in
// argon2id.html for the split of work between host and device.

const MASK64 = (1n << 64n) - 1n;

const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const rotr64 = (x, n) => {
  const k = BigInt(n);
  return ((x >> k) | (x << (64n - k))) & MASK64;
};

class Blake2b {
  constructor(outlen) {
    this.outlen = outlen;
    this.h = IV.slice();
    // blake2b_param: digest_length, key_length, fanout=1, depth=1, the rest 0
    this.h[0] ^= BigInt(outlen) | (1n << 16n) | (1n << 24n);
    this.t = [0n, 0n];
    this.f = [0n, 0n];
    this.buf = new Uint8Array(128);
    this.buflen = 0;
  }

  increment(inc) {
    const before = this.t[0];
    this.t[0] = (before + BigInt(inc)) & MASK64;
    if (this.t[0] < before) this.t[1] = (this.t[1] + 1n) & MASK64;
  }

  update(bytes) {
    const inlen = bytes.length;
    if (inlen === 0) return;
    let pin = 0;
    if (this.buflen + inlen > 128) {
      const fill = 128 - this.buflen;
      this.buf.set(bytes.subarray(0, fill), this.buflen);
      this.increment(128);
      this.compress(this.buf);
      this.buflen = 0;
      pin = fill;
      while (inlen - pin > 128) {
        this.increment(128);
        this.compress(bytes.subarray(pin, pin + 128));
        pin += 128;
      }
    }
    this.buf.set(bytes.subarray(pin), this.buflen);
    this.buflen += inlen - pin;
  }

  compress(block) {
    const dv = new DataView(block.buffer, block.byteOffset, 128);
    const m = new Array(16);
    for (let i = 0; i < 16; i++) m[i] = dv.getBigUint64(8 * i, true);
    const v = new Array(16);
    for (let i = 0; i < 8; i++) v[i] = this.h[i];
    v[8] = IV[0]; v[9] = IV[1]; v[10] = IV[2]; v[11] = IV[3];
    v[12] = IV[4] ^ this.t[0];
    v[13] = IV[5] ^ this.t[1];
    v[14] = IV[6] ^ this.f[0];
    v[15] = IV[7] ^ this.f[1];

    const G = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + m[x]) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 32);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 24);
      v[a] = (v[a] + v[b] + m[y]) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 63);
    };

    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r];
      G(0, 4, 8, 12, s[0], s[1]);
      G(1, 5, 9, 13, s[2], s[3]);
      G(2, 6, 10, 14, s[4], s[5]);
      G(3, 7, 11, 15, s[6], s[7]);
      G(0, 5, 10, 15, s[8], s[9]);
      G(1, 6, 11, 12, s[10], s[11]);
      G(2, 7, 8, 13, s[12], s[13]);
      G(3, 4, 9, 14, s[14], s[15]);
    }

    for (let i = 0; i < 8; i++) this.h[i] = this.h[i] ^ v[i] ^ v[i + 8];
  }

  final() {
    this.increment(this.buflen);
    this.f[0] = MASK64;                       // last block
    this.buf.fill(0, this.buflen, 128);
    this.compress(this.buf);
    const out = new Uint8Array(64);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setBigUint64(8 * i, this.h[i], true);
    return out.slice(0, this.outlen);
  }
}

export function blake2b(outlen, input) {
  const s = new Blake2b(outlen);
  s.update(input);
  return s.final();
}

const u32le = (x) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, x >>> 0, true);
  return b;
};

const concat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

/** blake2b_long() from blake2b.c: expand a digest to an arbitrary length. */
export function blake2bLong(outlen, input) {
  const prefix = u32le(outlen);
  if (outlen <= 64) return blake2b(outlen, concat(prefix, input));

  const out = new Uint8Array(outlen);
  let buf = blake2b(64, concat(prefix, input));
  out.set(buf.subarray(0, 32), 0);
  let pos = 32;
  let toproduce = outlen - 32;
  while (toproduce > 64) {
    buf = blake2b(64, buf);
    out.set(buf.subarray(0, 32), pos);
    pos += 32;
    toproduce -= 32;
  }
  buf = blake2b(toproduce, buf);
  out.set(buf.subarray(0, toproduce), pos);
  return out;
}

/* ---------------------------- Argon2id host side ---------------------------- */

export const ARGON2 = {
  lanes: 1, outlen: 32, mCost: 19456, tCost: 2, version: 0x13, type: 2, /* Argon2_id */
};

/** H0 = blake2b_512(LE32 params || LE32 pwdlen || pwd || LE32 saltlen || salt ||
 *                  LE32 secretlen || LE32 adlen) — initial_hash() in core.c. */
export function h0(password, salt, p = ARGON2) {
  const s = new Blake2b(64);
  s.update(u32le(p.lanes));
  s.update(u32le(p.outlen));
  s.update(u32le(p.mCost));
  s.update(u32le(p.tCost));
  s.update(u32le(p.version));
  s.update(u32le(p.type));
  s.update(u32le(password.length));
  s.update(password);
  s.update(u32le(salt.length));
  s.update(salt);
  s.update(u32le(0));                        // secretlen, no secret
  s.update(u32le(0));                        // adlen, no associated data
  return s.final();
}

/** B0 = H'(H0 || LE32(0) || LE32(lane)), B1 = H'(H0 || LE32(1) || LE32(lane)). */
export function firstBlocks(h0bytes, lane = 0) {
  const seed = new Uint8Array(72);
  seed.set(h0bytes, 0);
  const dv = new DataView(seed.buffer);
  dv.setUint32(64, 0, true);
  dv.setUint32(68, lane, true);
  const b0 = blake2bLong(1024, seed);
  dv.setUint32(64, 1, true);
  const b1 = blake2bLong(1024, seed);
  return { b0, b1 };
}

/** The tag: H'(C, outlen) over the final 1 KiB block (one lane, so no XOR). */
export function tagFromFinalBlock(finalBlock, outlen = 32) {
  return blake2bLong(outlen, finalBlock);
}

/**
 * Anubis's salt: 8 bytes, the u32 nonce in bytes 0..3 little-endian if the last
 * challenge byte is >= 0x80 (bytes 4..7 zero), otherwise the nonce in bytes
 * 4..7 big-endian (bytes 0..3 zero). Copied from wasm/argon2id_pow.c.
 */
export function anubisSalt(challenge, nonce) {
  const salt = new Uint8Array(8);
  const le = challenge.length > 0 && challenge[challenge.length - 1] >= 0x80;
  const n = nonce >>> 0;
  if (le) {
    salt[0] = n & 255; salt[1] = (n >>> 8) & 255;
    salt[2] = (n >>> 16) & 255; salt[3] = (n >>> 24) & 255;
  } else {
    salt[7] = n & 255; salt[6] = (n >>> 8) & 255;
    salt[5] = (n >>> 16) & 255; salt[4] = (n >>> 24) & 255;
  }
  return salt;
}

/** Everything the GPU needs for one nonce: the 2048 bytes of B0||B1. */
export function initialBlocks(challenge, nonce) {
  const salt = anubisSalt(challenge, nonce);
  return firstBlocks(h0(challenge, salt));
}
