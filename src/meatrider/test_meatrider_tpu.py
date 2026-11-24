#!/usr/bin/env python3
"""
The `meatrider` tier on a TPU: check the StableHLO, then run it if there is one.

`src/google/tpu/tpu_backend.c` builds the device program as StableHLO text and
hands it to PJRT, which is the only way a TPU is reachable from C here. The
builder is exposed as `anubis_tpu_meatrider_hlo()`, so this script can read the
program the device would be asked to run on a machine with no TPU at all:

    python3 src/meatrider/test_meatrider_tpu.py            # structure only
    python3 src/meatrider/test_meatrider_tpu.py --dump /tmp/mr.hlo

and on a TPU VM (Colab: Runtime -> TPU) it goes further: it mines a real rung and
re-derives the winning digest in C. If `libtpu.so` is not on the loader's default
path, point at it with ANUBIS_TPU_LIB=/path/to/libtpu.so.

What the structural checks are worth, stated plainly: they prove the module text
has the shape this tier needs -- two SHA-256 compressions, the display-order byte
swap, one comparison per 32 bits of difficulty -- and nothing about whether XLA
compiles it. Only the TPU run answers that.
"""

from __future__ import annotations

import argparse
import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LIB = ROOT / "libanubis_solver.so"
sys.path.insert(0, str(ROOT / "tools"))
import meatrider_ref  # noqa: E402

passed = failed = 0


def check(ok: bool, what: str) -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok   {what}")
    else:
        failed += 1
        print(f"  FAIL {what}")


class Ctx(ctypes.Structure):
    _fields_ = [
        ("first", ctypes.c_uint8 * 64),
        ("mid", ctypes.c_uint32 * 8),
        ("bits", ctypes.c_uint32),
        ("difficulty", ctypes.c_int),
        ("tail", ctypes.c_uint8 * 12),
        ("tail_block", ctypes.c_uint8 * 64),
    ]


def load():
    lib = ctypes.CDLL(str(LIB))
    lib.meatrider_ctx_init.restype = ctypes.c_int
    lib.meatrider_ctx_init.argtypes = [ctypes.POINTER(Ctx), ctypes.c_char_p, ctypes.c_int]
    lib.anubis_tpu_meatrider_hlo.restype = ctypes.c_int
    lib.anubis_tpu_meatrider_hlo.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_int, ctypes.c_char_p,
        ctypes.c_size_t]
    lib.anubis_tpu_meatrider_available.restype = ctypes.c_int
    lib.anubis_tpu_meatrider_solve.restype = ctypes.c_int
    lib.anubis_tpu_meatrider_solve.argtypes = [
        ctypes.POINTER(Ctx), ctypes.c_uint32, ctypes.c_uint32, ctypes.c_double,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p]
    lib.anubis_tpu_available.restype = ctypes.c_int
    lib.anubis_tpu_info.restype = ctypes.c_char_p
    return lib


def hlo_for(lib, rd: bytes, difficulty: int, lanes: int, cap: int = 8 << 20) -> str:
    ctx = Ctx()
    if lib.meatrider_ctx_init(ctypes.byref(ctx), rd, difficulty) != 0:
        raise SystemExit("meatrider_ctx_init refused the challenge")
    tail = (ctypes.c_uint32 * 3)(
        *[int.from_bytes(bytes(ctx.tail[4 * i:4 * i + 4]), "little") for i in range(3)])
    buf = ctypes.create_string_buffer(cap)
    n = lib.anubis_tpu_meatrider_hlo(lanes, ctx.mid, tail, difficulty, buf, cap)
    if n < 0:
        raise SystemExit(f"anubis_tpu_meatrider_hlo returned {n}")
    return buf.value.decode()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump", type=Path, default=None, help="write the StableHLO here")
    ap.add_argument("--difficulty", type=int, default=20)
    ap.add_argument("--lanes", type=int, default=8)
    ap.add_argument("--bench", action="store_true",
                    help="after the runs, time repeated solves on one cached challenge")
    ap.add_argument("--bench-reps", type=int, default=3)
    ap.add_argument("--bench-difficulty", type=int, default=18)
    ap.add_argument("--budget", type=float, default=600000.0,
                    help="ms per solve, compile included (default 10 min: the first\n"
                         "call compiles ~857 KB of StableHLO, which is the slow part)")
    args = ap.parse_args()

    if not LIB.exists():
        print(f"error: {LIB} is not built; run make", file=sys.stderr)
        return 1
    lib = load()
    rd = bytes(range(32))

    print(f"the device program, {args.lanes} lanes, difficulty {args.difficulty}:")
    text = hlo_for(lib, rd, args.difficulty, args.lanes)
    lines = text.splitlines()
    print(f"  {len(lines):,} lines, {len(text):,} bytes")
    if args.dump:
        args.dump.write_text(text)
        print(f"  written to {args.dump}")

    check(text.startswith("module {\n") and text.rstrip().endswith("}"),
          "the module is a StableHLO module { ... }")
    check("@main" in text and "stablehlo.iota" in text,
          "one @main taking the nonce base, lanes from iota")
    check(text.count("stablehlo.iota") == 1, "one lane iota, not one per lane")
    check(text.count("func.func @main") == 1, "a single function")
    check(text.count("dense<1116352408>") == 2,
          "the same first round constant appears twice: two compressions")
    check(text.count("stablehlo.convert") == 1 and text.count("return ") == 1,
          "one predicate converted to the flag byte and returned")
    want_cmp = max(1, (args.difficulty + 31) // 32)
    check(text.count("comparison_direction EQ") >= want_cmp,
          f"at least {want_cmp} equality tests against zero for {args.difficulty} bits")
    check(text.count("stablehlo.shift_right_logical") > 300,
          "the rotates are shift pairs (the module is unrolled, not a loop)")
    check(text.count("(") == text.count(")") and text.count("{") == text.count("}"),
          "balanced parentheses and braces")

    # The same program at a larger difficulty must test more words.
    small = hlo_for(lib, rd, 8, args.lanes)
    big = hlo_for(lib, rd, 64, args.lanes)
    check(big.count("comparison_direction EQ") > small.count("comparison_direction EQ"),
          "difficulty 64 emits more zero tests than difficulty 8")

    print("\nis a TPU reachable?")
    available = lib.anubis_tpu_meatrider_available()
    info = lib.anubis_tpu_info()
    print(f"  anubis_tpu_available: {lib.anubis_tpu_available()}, "
          f"meatrider: {available}, info: {(info or b'(none)').decode()}")
    if not available:
        print("  -> structure only; set ANUBIS_TPU_LIB and select a TPU runtime to go further")
        print(f"\n{passed} passed, {failed} failed")
        return 1 if failed else 0

    print("\na real search on the TPU:")
    for difficulty in (12, 20):
        ctx = Ctx()
        lib.meatrider_ctx_init(ctypes.byref(ctx), rd, difficulty)
        nonce = ctypes.c_uint32(0)
        digest = ctypes.create_string_buffer(32)
        print(f"  difficulty {difficulty}: compiling and mining (the first call pays the compile)")
        rc = lib.anubis_tpu_meatrider_solve(ctypes.byref(ctx), 0, 0, args.budget,
                                            ctypes.byref(nonce), digest)
        want = meatrider_ref.digest(rd, difficulty, nonce.value).hex() if rc == 0 else ""
        check(rc == 0 and digest.raw.hex() == want,
              f"difficulty {difficulty}: nonce {nonce.value}, digest agrees with the reference")

    if args.bench:
        print(f"\nthroughput at difficulty {args.bench_difficulty} "
              f"({args.bench_reps} solves, one cached executable):")
        ctx = Ctx()
        lib.meatrider_ctx_init(ctypes.byref(ctx), rd, args.bench_difficulty)
        nonce = ctypes.c_uint32(0)
        digest = ctypes.create_string_buffer(32)
        # The first call compiles; the timed ones do not.
        rc = lib.anubis_tpu_meatrider_solve(ctypes.byref(ctx), 0, 0, args.budget,
                                           ctypes.byref(nonce), digest)
        if rc != 0:
            check(False, f"bench warm-up returned {rc}")
        else:
            import time as _time
            started = _time.perf_counter()
            ok = True
            for _ in range(args.bench_reps):
                rc = lib.anubis_tpu_meatrider_solve(ctypes.byref(ctx), 0, 0,
                                                    args.budget, ctypes.byref(nonce),
                                                    digest)
                ok = ok and rc == 0
            elapsed = _time.perf_counter() - started
            hashes = args.bench_reps * (2 ** args.bench_difficulty)
            check(ok, f"{args.bench_reps} solves of 2^{args.bench_difficulty} in "
                      f"{elapsed:.2f} s = {hashes / elapsed / 1e6:.2f} MHash/s")
            print("  (the executable is cached, so this is dispatch + windows, not compile)")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
