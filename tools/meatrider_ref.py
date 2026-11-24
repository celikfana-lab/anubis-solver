#!/usr/bin/env python3
"""Reference implementation of the `meatrider` tier, in Python.

`meatrider` is the Bitcoin-shaped tier: SHA-256, twice, over a real 80-byte
block header rebuilt from the challenge. This file exists to be the second
implementation: `tests/test_meatrider.py` checks libanubis_solver.so against it,
so a bug has to happen twice, in two languages, to get through.

Specification (also in src/meatrider/meatrider.h):

    0..3    version    = 1                     little-endian u32
    4..35   prev block = randomData[0..32)
    36..67  merkle     = SHA256(b"meatrider" || randomData)
    68..71  time       = 1231006505            little-endian u32
    72..75  bits       = compact(2^(256-difficulty))
    76..79  nonce      = the client's u32, little-endian

    digest = reverse(SHA256(SHA256(header)))

The reversal is Bitcoin's display order, which is also the order in which the
leading-zero-bit test (`hash < 2^(256-difficulty)`) applies.

    ./tools/meatrider_ref.py            # the ladder, as the gates print it
    ./tools/meatrider_ref.py --digest <challenge_hex> <difficulty> <nonce>
    ./tools/meatrider_ref.py --mine <challenge_hex> <difficulty>
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import time

VERSION = 1
TIME = 1231006505  # the genesis block, 2009-01-03 18:15:05 UTC
LABEL = b"meatrider"

DEFAULT_USD_PER_TH_DAY = 0.05
S21_PRO_HASHRATE = 2.34e14  # 234 TH/s

#: The rungs, in USD, cheapest first. The name is the amount the tier asks for;
#: `difficulty_for_usd()` turns it into the leading-zero-bit count the challenge
#: carries. The ladder is a joke with a straight face: the amounts are real.
TIERS = [
    (1e-15, "spark"),
    (1e-14, "grain"),
    (1e-13, "speck"),
    (1e-12, "mote"),
    (1e-11, "crumb"),
    (1e-10, "atom"),
    (1e-9, "nano"),
    (1e-8, "microbit"),
    (1e-7, "dust"),
    (1e-6, "suspicious"),
    (1e-5, "very-suspicious"),
    (1e-4, "bot-shaped"),
    (1e-3, "farm"),
    (1e-2, "datacenter"),
    (1e-1, "asic"),
    (1e0, "meatrider"),
]


def compact(target: int) -> int:
    """Bitcoin's nBits for an exact target (arith_uint256::GetCompact)."""
    size = (target.bit_length() + 7) // 8
    c = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if c & 0x00800000:
        c >>= 8
        size += 1
    return c | (size << 24)


def target_from_compact(bits: int) -> int:
    exp = bits >> 24
    mant = bits & 0x007FFFFF
    return mant >> (8 * (3 - exp)) if exp <= 3 else mant << (8 * (exp - 3))


def header(rd: bytes, difficulty: int, nonce: int) -> bytes:
    """The 80-byte header. `rd` is the hex-decoded randomData (32 bytes)."""
    if len(rd) != 32:
        raise ValueError(f"randomData must be 32 bytes, got {len(rd)}")
    if not 1 <= difficulty <= 255:
        raise ValueError("difficulty must be 1..255 for meatrider")
    merkle = hashlib.sha256(LABEL + rd).digest()
    return (struct.pack("<I", VERSION) + rd + merkle
            + struct.pack("<III", TIME, compact(1 << (256 - difficulty)), nonce))


def digest(rd: bytes, difficulty: int, nonce: int) -> bytes:
    """The tier's hash, in Bitcoin display order."""
    h = hashlib.sha256(hashlib.sha256(header(rd, difficulty, nonce)).digest()).digest()
    return h[::-1]


def leading_zero_bits(h: bytes) -> int:
    n = 0
    for b in h:
        if b:
            return n + 8 - b.bit_length()
        n += 8
    return n


def solve(rd: bytes, difficulty: int, limit: int | None = None) -> tuple[int, bytes]:
    """Scalar search. Only useful for small difficulties; the C engine is the
    thing anyone should run."""
    for nonce in range(0 if limit is None else limit):
        d = digest(rd, difficulty, nonce)
        if leading_zero_bits(d) >= difficulty:
            return nonce, d
    raise RuntimeError("no nonce in range")


def price_usd(difficulty: int, usd_per_th_day: float = 0.0) -> float:
    if usd_per_th_day <= 0:
        usd_per_th_day = DEFAULT_USD_PER_TH_DAY
    return (1 << difficulty) * usd_per_th_day / (1e12 * 86400)


def asic_seconds(difficulty: int, hashrate: float = 0.0) -> float:
    return (1 << difficulty) / (hashrate or S21_PRO_HASHRATE)


def difficulty_for_usd(usd: float, usd_per_th_day: float = 0.0) -> int:
    d = 1
    while price_usd(d, usd_per_th_day) < usd and d < 255:
        d += 1
    return d


def tier_name(difficulty: int) -> str:
    price = price_usd(difficulty)
    name = TIERS[0][1]
    for usd, n in TIERS:
        if price >= usd:
            name = n
    return name


def human_seconds(s: float) -> str:
    if s < 1e-6:
        return f"{s * 1e9:.0f} ns"
    if s < 1e-3:
        return f"{s * 1e6:.0f} us"
    if s < 1:
        return f"{s * 1e3:.0f} ms"
    if s < 90:
        return f"{s:.0f} s"
    if s < 5400:
        return f"{s / 60:.0f} min"
    if s < 172800:
        return f"{s / 3600:.1f} h"
    if s < 3.16e7:
        return f"{s / 86400:.0f} days"
    years = s / 3.156e7
    if years < 1e6:
        return f"{years:.0f} years"
    return f"{years:.1e} years"


def ladder(hps: float = 1e6, usd_per_th_day: float = 0.0) -> str:
    """The table the gates print, one rung per line."""
    out = [
        "rung              usd asked   difficulty   expected hashes"
        "   ASIC time      browser time (%.0f H/s)" % hps,
    ]
    for usd, name in TIERS:
        d = difficulty_for_usd(usd, usd_per_th_day)
        actual = price_usd(d, usd_per_th_day)
        out.append(
            f"{name:<16} ${usd:<10.0e} d={d:<9d} 2^{d} = {2.0 ** d:.1e}"
            f"   {human_seconds(asic_seconds(d)):<13} {human_seconds((1 << d) / hps)}"
            f"   (worth ${actual:.2e})"
        )
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--digest", nargs=3, metavar=("CHALLENGE_HEX", "DIFFICULTY", "NONCE"))
    ap.add_argument("--mine", nargs=2, metavar=("CHALLENGE_HEX", "DIFFICULTY"))
    ap.add_argument("--ladder", action="store_true")
    ap.add_argument("--hps", type=float, default=1e6,
                    help="browser hashes/second for the time column (default 1e6, "
                         "the wasm kernel; the pure-JS fallback is ~10x slower)")
    args = ap.parse_args(argv)

    if args.digest:
        chal, diff, nonce = args.digest
        d = digest(bytes.fromhex(chal), int(diff), int(nonce))
        print(d.hex())
        print(f"leading zero bits: {leading_zero_bits(d)}")
        return 0
    if args.mine:
        chal, diff = args.mine
        t0 = time.perf_counter()
        nonce, d = solve(bytes.fromhex(chal), int(diff))
        print(f"nonce={nonce} {d.hex()} in {time.perf_counter() - t0:.2f}s")
        return 0
    print(ladder(args.hps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
