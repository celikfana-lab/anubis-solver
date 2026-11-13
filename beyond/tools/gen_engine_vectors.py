#!/usr/bin/env python3
"""Vectors for beyond/tb_argon2_engine.v: a whole Argon2id hash.

The testbench instantiates the engine with M_COST = 64 (a real 19 MiB run is
millions of cycles), so the reference uses memory_cost = 64 too. One line per
case: plen, salt, expected tag (hex), password bytes written to a .hex file.
"""
import struct
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw

M_COST, T_COST, TAGLEN = 64, 2, 32

CASES = [
    (b"anubis-test-password", 0x0123456789ABCDEF),
    (b"x", 1),
    (bytes(range(96)), 0xFEDCBA9876543210),
]


def main():
    here = Path(__file__).resolve().parent.parent / "vectors"
    lines = []
    pw = []
    for p, salt in CASES:
        tag = hash_secret_raw(p, salt.to_bytes(8, "little"),
                              time_cost=T_COST, memory_cost=M_COST,
                              parallelism=1, hash_len=TAGLEN,
                              type=Type.ID, version=0x13)
        lines.append("%08x%08x" % (len(p), salt & 0xFFFFFFFF))
        lines.append("%08x" % (salt >> 32))
        lines.append(tag.hex())
        assert len(p) <= 192
        pw.extend("%02x" % b for b in bytes(p).ljust(192, b"\0"))
    (here / "engine_vectors.hex").write_text("\n".join(lines) + "\n")
    (here / "engine_pw.hex").write_text("\n".join(pw) + "\n")
    print(f"wrote engine_vectors.hex ({len(CASES)} cases) and engine_pw.hex",
          file=sys.stderr)


if __name__ == "__main__":
    main()
