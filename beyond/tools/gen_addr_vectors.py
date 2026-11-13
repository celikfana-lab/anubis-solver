#!/usr/bin/env python3
"""Vectors for beyond/tb_argon2_addr.v: Argon2id address blocks.

Per case: 8 parameter lines then 128 expected 64-bit words (hex, one per line):
    pass, lane, slice, m', t, y, counter, unused
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_argon_vectors import fill_block  # verified against argon2-cffi by tb_argon2_fill

ZERO = [0] * 128


def addr_block(p, l, s, m, t, y, ctr):
    Z = [p, l, s, m, t, y, ctr] + [0] * 121
    a1 = fill_block(ZERO, Z, ZERO, 0)          # A1 = G(0, Z)
    return fill_block(ZERO, a1, ZERO, 0)       # A  = G(0, A1)


# counter values start at 1: next_addresses() increments v[6] before hashing
CASES = [
    (0, 0, 0, 19456, 2, 2, 1),
    (0, 0, 0, 19456, 2, 2, 2),
    (0, 0, 1, 19456, 2, 2, 38),
    (1, 0, 2, 19456, 2, 2, 6),
    (0, 3, 1, 65536, 3, 1, 129),
]


def main(path="vectors/addr_vectors.hex"):
    out = []
    for p, l, s, m, t, y, ctr in CASES:
        out.extend("%016x" % v for v in (p, l, s, m, t, y, ctr, 0))
        out.extend("%016x" % w for w in addr_block(p, l, s, m, t, y, ctr))
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {path}: {len(CASES)} cases", file=sys.stderr)


if __name__ == "__main__":
    main()
