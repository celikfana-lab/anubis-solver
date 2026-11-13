#!/usr/bin/env python3
"""Vectors for beyond/tb_h_prime.v: Argon2's H' against hashlib.

Per case, 2056 bytes:
    [0..1023]    X, zero padded
    [1024..1027] |X|, 32-bit LE
    [1028..1031] tau, 32-bit LE
    [1032..2055] expected output, 1024 bytes (first tau are meaningful)
"""
import hashlib
import struct
import sys

CASE = 2056


def H_prime(X: bytes, tau: int) -> bytes:
    if tau <= 64:
        return hashlib.blake2b(struct.pack("<I", tau) + X, digest_size=tau).digest()
    r = tau // 32 - 2
    V = hashlib.blake2b(struct.pack("<I", tau) + X, digest_size=64).digest()
    out = bytearray(V[:32])
    for _ in range(2, r + 1):
        V = hashlib.blake2b(V, digest_size=64).digest()
        out += V[:32]
    out += hashlib.blake2b(V, digest_size=tau - 32 * r).digest()
    return bytes(out)


block_b = bytes(((i * 7) + 3) & 0xFF for i in range(1024))
CASES = [
    (bytes(range(72)), 1024),   # seeding a lane: H'(1024, H0 || i || j)
    (block_b, 64),              # the tag
    (block_b, 32),              # short output, tau <= 64 path
    (bytes(range(72)), 96),     # just above one block: r=1, 32+64
]


def main(path="vectors/hp_vectors.hex"):
    out = []
    for X, tau in CASES:
        assert len(X) <= 1024
        blk = bytearray(CASE)
        blk[0:len(X)] = X
        blk[1024:1028] = struct.pack("<I", len(X))
        blk[1028:1032] = struct.pack("<I", tau)
        blk[1032:1032 + len(H_prime(X, tau))] = H_prime(X, tau)
        out.extend("%02x" % b for b in blk)
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {path}: {len(CASES)} cases, {len(out)} bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
