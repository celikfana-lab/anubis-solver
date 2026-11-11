#!/usr/bin/env python3
"""Unit tests for the C core, checked against Python's hashlib."""

from __future__ import annotations

import hashlib
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisChallenge, AnubisSolver

FAILS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global FAILS
    if cond:
        print(f"  ok   {name}")
    else:
        FAILS += 1
        print(f"  FAIL {name} {detail}")


def nibbles_ok(digest_hex: str, difficulty: int) -> bool:
    return digest_hex.startswith("0" * difficulty)


def bits_ok(digest_hex: str, difficulty: int) -> bool:
    raw = bytes.fromhex(digest_hex)
    full, rem = divmod(difficulty, 8)
    if any(b != 0 for b in raw[:full]):
        return False
    if rem and (raw[full] & (0xFF << (8 - rem))):
        return False
    return True


def main() -> int:
    solver = AnubisSolver()
    print(f"native solver {solver.version}, threads={solver.threads}")

    print("SHA-256 correctness")
    for data in [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"a" * 1000]:
        want = hashlib.sha256(data).hexdigest()
        got = solver.sha256_hex(data)
        check(f"sha256({len(data)} bytes)", got == want, f"{got} != {want}")

    print("fast/slow challenge (leading zero nibbles)")
    for difficulty in (1, 2, 3, 4, 5):
        challenge = os.urandom(8).hex()  # randomData is 64 bytes in practice
        nonce, response, elapsed = solver._native.solve_nibbles(
            challenge, difficulty, solver.threads, 0
        )
        want = hashlib.sha256(f"{challenge}{nonce}".encode()).hexdigest()
        ok = nibbles_ok(want, difficulty)
        check(
            f"difficulty={difficulty} nonce={nonce}",
            ok and response == want,
            f"hash={want[:16]} nonce={nonce}",
        )
        print(f"       ({elapsed:.1f} ms)")
        # verify() must agree
        ch = AnubisChallenge(
            id="x",
            random_data=challenge,
            algorithm="fast",
            difficulty=difficulty,
        )
        check(f"verify_nibbles difficulty={difficulty}", solver.verify(ch, nonce))

    print("wasm sha256 challenge (leading zero bits)")
    for difficulty in (8, 12, 16, 20):
        # Exercise both nonce encodings: last byte >= 0x80 -> little-endian.
        for last_byte_le in (False, True):
            raw = bytearray(os.urandom(64))
            raw[-1] = random.choice([0x00, 0x7F]) if not last_byte_le else random.choice([0x80, 0xFF])
            challenge_hex = bytes(raw).hex()
            nonce, response, elapsed = solver._native.solve_bits(
                challenge_hex, difficulty, solver.threads, 0
            )

            use_le = raw[-1] >= 0x80
            suffix = nonce.to_bytes(4, "little" if use_le else "big")
            want = hashlib.sha256(bytes(raw) + suffix).hexdigest()
            check(
                f"difficulty={difficulty} le={use_le} nonce={nonce}",
                bits_ok(want, difficulty) and response == want,
            )
            print(f"       ({elapsed:.1f} ms)")

            ch = AnubisChallenge(
                id="x",
                random_data=challenge_hex,
                algorithm="sha256",
                difficulty=difficulty,
            )
            check(f"verify_bits difficulty={difficulty} le={use_le}", solver.verify(ch, nonce))

    print("wasm argon2id challenge (leading zero bits)")
    try:
        from argon2.low_level import Type as Argon2Type
        from argon2.low_level import hash_secret_raw

        have_argon2 = True
    except ImportError:
        have_argon2 = False
        print("  (argon2-cffi not installed: cross-check skipped)")

    for difficulty in (1, 2):
        for last_byte in (0x00, 0xFF):
            raw = bytearray(os.urandom(64))
            raw[-1] = last_byte
            challenge_hex = bytes(raw).hex()
            use_le = last_byte >= 0x80
            nonce, response, elapsed = solver._native.solve_argon2id(
                challenge_hex, difficulty, min(solver.threads, 4), 0
            )
            salt = nonce.to_bytes(8, "little" if use_le else "big")
            if have_argon2:
                want = hash_secret_raw(
                    bytes(raw),
                    salt,
                    time_cost=2,
                    memory_cost=19456,
                    parallelism=1,
                    hash_len=32,
                    type=Argon2Type.ID,
                ).hex()
                check(
                    f"argon2id difficulty={difficulty} le={use_le} matches argon2-cffi",
                    response == want,
                )
            ch = AnubisChallenge(
                id="x", random_data=challenge_hex, algorithm="argon2id", difficulty=difficulty
            )
            check(
                f"verify_argon2id difficulty={difficulty} le={use_le}",
                bits_ok(response, difficulty) and solver.verify(ch, nonce),
            )
            print(f"       ({elapsed:.1f} ms)")

    print("wasm hashx challenge (leading zero bits)")
    for difficulty in (5, 8, 10):
        raw = os.urandom(64)
        challenge_hex = raw.hex()
        nonce, response, elapsed = solver._native.solve_hashx(
            challenge_hex, difficulty, solver.threads, 0
        )
        ch = AnubisChallenge(
            id="x", random_data=challenge_hex, algorithm="hashx", difficulty=difficulty
        )
        check(
            f"hashx difficulty={difficulty} nonce={nonce}",
            bits_ok(response, difficulty) and solver.verify(ch, nonce),
        )
        print(f"       ({elapsed:.1f} ms)")

    print("negative verification")
    ch = AnubisChallenge(id="x", random_data="00" * 64, algorithm="fast", difficulty=4)
    check("wrong nonce rejected", not solver.verify(ch, 1))

    print()
    if FAILS:
        print(f"{FAILS} check(s) FAILED")
        return 1
    print("all core checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
