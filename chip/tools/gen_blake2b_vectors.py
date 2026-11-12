#!/usr/bin/env python3
"""Generate byte-stream BLAKE2b vectors for chip/tb_blake2b_stream.v.

Layout, NC blocks of 512 bytes each:
    [0..255]    message bytes, zero padded
    [256..263]  message length, 64-bit LE
    [264..267]  digest length tau, 32-bit LE
    [268..331]  expected digest, 8 x 64-bit little-endian words (full 512-bit h,
                only the first tau bytes are meaningful)
"""
import hashlib
import struct
import sys

NC = 6
BLOCK = 512


def h0_like():
    """40-byte H0 prefix + a 64-byte password + 28 bytes of salt/lengths."""
    pw = bytes(range(64))
    pre = struct.pack("<6I", 1, 19, 19456, 2, 0x13, 2) + struct.pack("<I", len(pw))
    salt = b"anubisno"
    post = struct.pack("<I", len(salt)) + salt + struct.pack("<I", 0) + struct.pack("<I", 0)
    return pre + pw + post


CASES = [
    (b"", 64),
    (b"abc", 64),
    (b"a" * 128, 64),
    (b"a" * 200, 64),
    (h0_like(), 64),
    (bytes(range(64)), 32),
]


def main(path="vectors/b2_vectors.hex"):
    assert len(CASES) == NC
    out = []
    for msg, tau in CASES:
        assert len(msg) <= 256
        blk = bytearray(BLOCK)
        blk[0:len(msg)] = msg
        blk[256:264] = struct.pack("<Q", len(msg))
        blk[264:268] = struct.pack("<I", tau)
        want = hashlib.blake2b(msg, digest_size=tau).digest().ljust(64, b"\0")
        blk[268:332] = want
        out.extend("%02x" % b for b in blk)
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {path}: {NC} cases, {len(out)} bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
