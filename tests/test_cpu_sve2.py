#!/usr/bin/env python3
"""Parity and speed for the SVE2 batch kernel (src/cpu/arm/sve2.s).

The kernel hashes N candidate messages that share a midstate:

    void sha256_compress_sve2(const uint32_t mid[8],
                              const uint8_t tails[][64],
                              uint8_t out[][32]);

where N is SVC (svcntw(): 4 on a 128-bit core such as Neoverse N2). This file
checks it against hashlib, using the same shape the `fast`/`slow` tiers build:
a 64-byte prefix folded into `mid`, then one padded tail block per candidate.

The check is skipped, not failed, on a machine without SVE2 or without the
kernel compiled in; the arm64 CI jobs are what run it for real.
"""

import ctypes
import hashlib
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
M32 = 0xFFFFFFFF

checks = 0
failures = 0


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def compress(state, block):
    """SHA-256 compression of one 64-byte block into `state`."""
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = state
    for t in range(64):
        big1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + big1 + ch + K[t] + w[t]) & M32
        big0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big0 + maj) & M32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
    return [(x + y) & M32 for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def padded_tail(prefix_len, suffix):
    """The one padded block that finishes a message with this suffix."""
    assert len(suffix) <= 55
    tail = bytearray(64)
    tail[:len(suffix)] = suffix
    tail[len(suffix)] = 0x80
    struct.pack_into(">Q", tail, 56, (prefix_len + len(suffix)) * 8)
    return bytes(tail)


def check(name, got, want):
    global checks, failures
    checks += 1
    if got != want:
        failures += 1
        print("  FAIL %s\n    got  %s\n    want %s" % (name, got.hex(), want.hex()))


def main():
    if os.uname().machine not in ("aarch64", "arm64"):
        print("skip: not an aarch64 machine")
        return 0
    lib = ctypes.CDLL(os.path.join(ROOT, "libanubis_solver.so"))
    if not hasattr(lib, "sha256_compress_sve2"):
        print("skip: this build has no SVE2 kernel (compiled for another arch)")
        return 0
    with open("/proc/cpuinfo") as f:
        feats = "".join(line for line in f if line.startswith("Features"))
    if "sve2" not in feats:
        print("skip: CPU does not report sve2")
        return 0

    lib.sha256_sve2_width.restype = ctypes.c_long
    lanes = lib.sha256_sve2_width()
    print("SVE2 kernel: %d lanes (%ld bits)" % (lanes, lanes * 32))
    assert lanes in (4, 8, 16), lanes

    # 64-byte prefix, so mid is the state after one full block
    prefix = bytes(range(64))
    mid_words = compress(IV, prefix)
    mid = (ctypes.c_uint32 * 8)(*mid_words)
    tails = (ctypes.c_uint8 * (lanes * 64))()
    out = (ctypes.c_uint8 * (lanes * 32))()

    # hashlib is the independent oracle: prefix + suffix, digested in one go
    trial = 0
    for base in (0, 7, 999_999, 2**32 - 3, 123_456_789):
        for step in range(1, 41):
            for lane in range(lanes):
                suffix = str(base + step * lane).encode()
                tails[lane * 64:(lane + 1) * 64] = padded_tail(64, suffix)
            lib.sha256_compress_sve2(mid, tails, out)
            for lane in range(lanes):
                suffix = str(base + step * lane).encode()
                want = hashlib.sha256(prefix + suffix).digest()
                got = bytes(out[lane * 32:(lane + 1) * 32])
                check("trial %d lane %d nonce %d" % (trial, lane, base + step * lane),
                      got, want)
            trial += 1
    print("parity: %d digests compared against hashlib" % checks)

    # speed: the SVE2 batch kernel against the 1-way crypto kernel it is
    # compared with in the dispatch, same padded blocks
    lib.sha256_block_neon.argtypes = [ctypes.POINTER(ctypes.c_uint32),
                                      ctypes.POINTER(ctypes.c_uint8)]
    state = (ctypes.c_uint32 * 8)(*mid_words)
    block = ctypes.cast(tails, ctypes.POINTER(ctypes.c_uint8))
    iters = 4000
    t0 = time.perf_counter()
    for _ in range(iters):
        lib.sha256_compress_sve2(mid, tails, out)
    sve2_ns = (time.perf_counter() - t0) * 1e9 / (iters * lanes)
    t0 = time.perf_counter()
    for _ in range(iters * lanes):
        lib.sha256_block_neon(state, block)
    neon_ns = (time.perf_counter() - t0) * 1e9 / (iters * lanes)
    print("  batch sve2 : %8.1f ns per candidate-block (%.1f cycles @2.6GHz)"
          % (sve2_ns, sve2_ns * 2.6))
    print("  neon+sha2  : %8.1f ns per candidate-block (%.1f cycles @2.6GHz)"
          % (neon_ns, neon_ns * 2.6))
    print("  ratio      : %.2fx (sve2 / neon+sha2)" % (sve2_ns / neon_ns))

    if failures:
        print("FAILED (%d of %d)" % (failures, checks))
        return 1
    print("all SVE2 kernel checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
