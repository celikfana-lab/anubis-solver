#!/usr/bin/env python3
"""Generate prev/ref/dst/expected hex files for tb_argon2_fill.v."""
from pathlib import Path

M = (1 << 64) - 1

def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M

def blamka(a, b):
    return (a + b + 2 * (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF)) & M

def g(v, a, b, c, d):
    v[a] = blamka(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = blamka(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = blamka(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = blamka(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 63)

PERM = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
OFF = [0, 1, 16, 17, 32, 33, 48, 49, 64, 65, 80, 81, 96, 97, 112, 113]

def round16(v, idx):
    for p in PERM:
        g(v, idx[p[0]], idx[p[1]], idx[p[2]], idx[p[3]])

def fill_block(prev, ref, dst, with_xor):
    r = [a ^ b for a, b in zip(prev, ref)]
    for i in range(8):
        idx = [16 * i + k for k in range(16)]
        round16(r, idx)
    for i in range(8):
        idx = [2 * i + OFF[k] for k in range(16)]
        round16(r, idx)
    return [r[i] ^ prev[i] ^ ref[i] ^ ((dst[i] if with_xor else 0)) for i in range(128)]

def main() -> int:
    prev = [(0x9E3779B97F4A7C15 * (i + 1)) & M for i in range(128)]
    ref = [(0x100000001B3 * (i + 7)) & M for i in range(128)]
    dst = [(0xDEADBEEFCAFEBABE ^ i) & M for i in range(128)]
    out = fill_block(prev, ref, dst, with_xor=1)
    here = Path(__file__).resolve().parent
    for name, words in (("prev.hex", prev), ("ref.hex", ref), ("dst.hex", dst),
                        ("expected.hex", out)):
        (here / name).write_text("\n".join(f"{w:016x}" for w in words) + "\n")
        print("wrote", name)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
