#!/usr/bin/env python3
"""The `meatrider` tier: the C engine against tools/meatrider_ref.py.

The tier is SHA-256d over an 80-byte Bitcoin block header rebuilt from the
challenge, so a wrong byte in the header is still a valid-looking hash and only
a second implementation catches it. That second implementation is plain Python
(hashlib) in tools/meatrider_ref.py, and every digest, header field, nBits value
and price here is checked against it.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import meatrider_ref as ref  # noqa: E402
from anubis_solver import AnubisChallenge, AnubisSolver  # noqa: E402

FAILS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global FAILS
    if cond:
        print(f"  ok   {name}")
    else:
        FAILS += 1
        print(f"  FAIL {name} {detail}")


CHALLENGES = [
    bytes.fromhex("00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef"),
    bytes.fromhex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221117"),
    bytes(range(32)),
]


def main() -> int:
    solver = AnubisSolver()
    py = solver._native
    print(f"native solver {solver.version}, threads={solver.threads}")

    # --- the header is Bitcoin's, field by field -------------------------
    print("header")
    for rd in CHALLENGES[:2]:
        for difficulty in (1, 8, 12, 20, 33, 61, 255):
            got = py.meatrider_header(rd.hex(), difficulty, 0xDEADBEEF)
            want = ref.header(rd, difficulty, 0xDEADBEEF)
            check(f"header {difficulty}", got == want.hex(), f"{got} != {want.hex()}")
            h = bytes.fromhex(got) if got else b""
            check(f"header {difficulty} length", len(h) == 80, str(len(h)))
            check(f"header {difficulty} version", int.from_bytes(h[0:4], "little") == ref.VERSION)
            check(f"header {difficulty} prev", h[4:36] == rd)
            check(f"header {difficulty} merkle",
                  h[36:68] == hashlib.sha256(ref.LABEL + rd).digest())
            check(f"header {difficulty} time",
                  int.from_bytes(h[68:72], "little") == ref.TIME)
            check(f"header {difficulty} bits",
                  int.from_bytes(h[72:76], "little") == ref.compact(1 << (256 - difficulty)))
            check(f"header {difficulty} nonce",
                  int.from_bytes(h[76:80], "little") == 0xDEADBEEF)

    # --- digests, and the nBits round trip -------------------------------
    print("digests")
    for rd in CHALLENGES:
        for difficulty in (1, 7, 8, 12, 16, 61):
            for nonce in (0, 1, 449, 0xFFFFFFFF):
                want = ref.digest(rd, difficulty, nonce)
                ok, got = py.verify_meatrider(rd.hex(), nonce, difficulty)
                check(f"digest d={difficulty} n={nonce}", got == want.hex(),
                      f"{got} != {want.hex()}")
                check(f"verdict d={difficulty} n={nonce}",
                      ok == (ref.leading_zero_bits(want) >= difficulty))

    print("nBits")
    for difficulty in range(1, 256):
        bits = py.meatrider_bits(difficulty)
        check(f"nBits d={difficulty}",
              bits == ref.compact(1 << (256 - difficulty))
              and ref.target_from_compact(bits) == 1 << (256 - difficulty))

    # --- solving, and the verifier's refusals ---------------------------
    print("solve")
    for difficulty in (8, 12, 16):
        rd = CHALLENGES[difficulty % len(CHALLENGES)]
        ch = AnubisChallenge(
            id="x", random_data=rd.hex(), algorithm="meatrider", difficulty=difficulty
        )
        sol = solver.solve(ch)
        want = ref.digest(rd, difficulty, sol.nonce)
        check(f"solve d={difficulty} digest", sol.response == want.hex(),
              f"{sol.response} != {want.hex()}")
        check(f"solve d={difficulty} leading bits", ref.leading_zero_bits(want) >= difficulty)
        check(f"solve d={difficulty} verifies", solver.verify(ch, sol.nonce))
        check(f"solve d={difficulty} elapsed", sol.elapsed_ms >= 0)

        # The target is a field of the header, so the same nonce hashes to a
        # different digest at another difficulty -- Bitcoin's nBits binds a
        # proof to the difficulty it was mined for.
        other = py.verify_meatrider(rd.hex(), sol.nonce, difficulty + 1)[1]
        check(f"difficulty is in the header d={difficulty}", other != want.hex())

    # --- refusals -------------------------------------------------------
    print("refusals")
    rd = CHALLENGES[0].hex()
    for bad, why in ((0, "difficulty 0"), (256, "difficulty 256")):
        try:
            py.verify_meatrider(rd, 0, bad)
            check(why + " rejected", False, "no error")
        except Exception:
            check(why + " rejected", True)
    try:
        py.verify_meatrider("00" * 31, 0, 8)
        check("31-byte randomData rejected", False, "no error")
    except Exception:
        check("31-byte randomData rejected", True)
    try:
        py.verify_meatrider("zz" * 32, 0, 8)
        check("non-hex rejected", False, "no error")
    except Exception:
        check("non-hex rejected", True)

    # --- the price ladder ----------------------------------------------
    print("ladder")
    check("d=11 is a femtocent rung", py.meatrider_tier(11) == "spark")
    check("d=28 is the atom-of-a-cent rung", py.meatrider_tier(28) == "atom")
    check("d=41 is suspicious", py.meatrider_tier(41) == "suspicious")
    check("d=61 is the meatrider rung", py.meatrider_tier(61) == "meatrider")
    for difficulty in (11, 28, 41, 61):
        check(f"price d={difficulty}",
              abs(py.meatrider_price_usd(difficulty, 0.0) - ref.price_usd(difficulty)) < 1e-30)
        check(f"asic seconds d={difficulty}",
              abs(py.meatrider_asic_seconds(difficulty, 0.0)
                  - ref.asic_seconds(difficulty)) / ref.asic_seconds(difficulty) < 1e-9)

    # "one dollar of bitcoin" must land on a rung whose ASIC time is hours
    d1 = py.meatrider_difficulty_for_usd(1.0, 0.0)
    check("$1 is difficulty 61", d1 == 61, str(d1))
    hours = ref.asic_seconds(d1) / 3600
    check("$1 is 2-3 ASIC hours", 2.0 < hours < 3.0, f"{hours:.2f} h")
    check("$1 is millions of browser years",
          ref.asic_seconds(d1) * 2.34e14 / 2000 / 3.156e7 > 1e7)

    # the names must be monotone and cover every difficulty the tier accepts
    last = -1
    order = {name: i for i, (_, name) in enumerate(ref.TIERS)}
    for difficulty in range(1, 256):
        name = py.meatrider_tier(difficulty)
        if name is None:
            check(f"tier name d={difficulty}", False, "None")
            break
        idx = order[name]
        if idx < last:
            check(f"tier names monotone at d={difficulty}", False, name)
            break
        last = idx
    else:
        check("tier names are monotone over 1..255", True)

    print()
    if FAILS:
        print(f"{FAILS} check(s) failed")
        return 1
    print("all meatrider checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
