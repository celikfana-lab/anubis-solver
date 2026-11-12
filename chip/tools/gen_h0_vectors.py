#!/usr/bin/env python3
"""Vectors for chip/tb_h0.v: Argon2's H0 against hashlib.

Per case, 272 bytes:
    [0..191]   password bytes, zero padded
    [192..195] |P|, LE32
    [196..199] T,   LE32
    [200..207] salt (the nonce), 8 bytes as the u64 little-endian
    [208..271] expected H0, 8 x 64-bit little-endian words
"""
import hashlib
import struct
import sys

CASE = 272
P, M, T, V, Y = 1, 19456, 2, 0x13, 2


def h0(P_bytes: bytes, salt: int, taglen: int) -> bytes:
    s = salt.to_bytes(8, "little")
    msg = (struct.pack("<6I", P, taglen, M, T, V, Y)
           + struct.pack("<I", len(P_bytes)) + P_bytes
           + struct.pack("<I", len(s)) + s
           + struct.pack("<I", 0) + struct.pack("<I", 0))
    return hashlib.blake2b(msg, digest_size=64).digest()


CASES = [
    (b"challenge-0123456789abcdef", 0x0123456789ABCDEF, 32),
    (b"x", 1, 32),
    (bytes(range(96)), 0xFEDCBA9876543210, 64),
]


def main(path="vectors/h0_vectors.hex"):
    out = []
    for pw, salt, taglen in CASES:
        assert len(pw) <= 192
        blk = bytearray(CASE)
        blk[0:len(pw)] = pw
        blk[192:196] = struct.pack("<I", len(pw))
        blk[196:200] = struct.pack("<I", taglen)
        blk[200:208] = salt.to_bytes(8, "little")
        want = h0(pw, salt, taglen)
        blk[208:208 + 64] = want
        out.extend("%02x" % b for b in blk)
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {path}: {len(CASES)} cases", file=sys.stderr)


if __name__ == "__main__":
    main()
