#!/usr/bin/env python3
"""Recheck a chip solve against argon2-cffi.

    ./verify_solve.py <challenge_hex> <nonce> <tag_hex> [m_cost] [difficulty]

Mirrors the Anubis argon2id rule: password = hex_decode(challenge), salt = the
nonce as a u64 (little-endian when the last challenge byte is >= 0x80), tag is
32 bytes of Argon2id v1.3 with t=2, p=1, and a hit needs `difficulty` leading
zero bits.
"""
import sys

from argon2.low_level import Type, hash_secret_raw


def leading_zero_bits(buf: bytes) -> int:
    n = 0
    for byte in buf:
        for bit in range(7, -1, -1):
            if byte >> bit & 1:
                return n
            n += 1
    return n


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 2
    challenge, nonce, tag_hex = argv[1], int(argv[2]), argv[3].lower()
    m_cost = int(argv[4]) if len(argv) > 4 else 19456
    difficulty = int(argv[5]) if len(argv) > 5 else 1

    raw = bytes.fromhex(challenge)
    use_le = raw[-1] >= 0x80
    salt = nonce.to_bytes(8, "little" if use_le else "big", signed=False)
    want = hash_secret_raw(raw, salt, time_cost=2, memory_cost=m_cost,
                           parallelism=1, hash_len=32, type=Type.ID, version=0x13)
    lz = leading_zero_bits(want)
    print(f"challenge {len(raw)} bytes, last byte {raw[-1]:#04x} -> "
          f"{'LE' if use_le else 'BE'} salt")
    print(f"m_cost {m_cost}, nonce {nonce}, salt {salt.hex()}")
    print(f"argon2-cffi tag {want.hex()}")
    print(f"chip tag        {tag_hex}")
    print(f"identical       {want.hex() == tag_hex}")
    print(f"leading zeros   {lz} (difficulty {difficulty}) -> "
          f"{'SOLVED' if lz >= difficulty and want.hex() == tag_hex else 'no'}")
    return 0 if want.hex() == tag_hex and lz >= difficulty else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
