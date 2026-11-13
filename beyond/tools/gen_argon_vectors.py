#!/usr/bin/env python3
"""Generate prev/ref/dst/expected hex files for tb_argon2_fill.v.

Each file holds TWO blocks: entries 0..127 are block A, 128..255 are block B.
The testbench runs them back to back with no idle cycle in between and checks
both, so a block-to-block hand-off bug fails here instead of three layers up
in tb_argon2_engine.
"""
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

def lcg_words(seed, n=128):
    """Deterministic pseudo-random block, so block B shares nothing with A."""
    x, out = seed, []
    for _ in range(n):
        x = (x * 6364136223846793005 + 1442695040888963407) & M
        out.append(x)
    return out


def main() -> int:
    prevA = [(0x9E3779B97F4A7C15 * (i + 1)) & M for i in range(128)]
    refA = [(0x100000001B3 * (i + 7)) & M for i in range(128)]
    dstA = [(0xDEADBEEFCAFEBABE ^ i) & M for i in range(128)]
    prevB = lcg_words(0x243F6A8885A308D3)
    refB = lcg_words(0x13198A2E03707344)
    dstB = lcg_words(0xA4093822299F31D0)
    cols = {"prev.hex": [], "ref.hex": [], "dst.hex": [], "expected.hex": []}
    for prev, ref, dst in ((prevA, refA, dstA), (prevB, refB, dstB)):
        out = fill_block(prev, ref, dst, with_xor=1)
        for name, words in (("prev.hex", prev), ("ref.hex", ref),
                            ("dst.hex", dst), ("expected.hex", out)):
            cols[name].extend(words)
    here = Path(__file__).resolve().parent.parent / "vectors"
    for name, words in cols.items():
        (here / name).write_text("\n".join(f"{w:016x}" for w in words) + "\n")
        print("wrote", name, len(words), "words")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
