#!/usr/bin/env python3
"""Cost of CPU re-verification of GPU hits (--no-verify-gpu / ANUBIS_GPU_NO_VERIFY).

    python3 tools/bench_gpu_verify.py                     # Argon2id
    ANUBIS_GPU_ARGON2=1 ANUBIS_GPU_HASHX=1 python3 tools/bench_gpu_verify.py --algo both
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisSolver  # noqa: E402


def one_verify_ms(lib, kind: str) -> float:
    import ctypes

    fn = getattr(lib, f"anubis_verify_{kind}")
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int,
                   ctypes.c_char_p]
    buf = ctypes.create_string_buffer(65)
    ts = []
    for _ in range(5):
        t0 = time.perf_counter()
        fn(b"ab" * 64, 12345, 8, buf)
        ts.append((time.perf_counter() - t0) * 1000)
    return statistics.median(ts)


def bench(solver: AnubisSolver, kind: str, difficulty: int, reps: int,
          verify: bool) -> float:
    solver._native.set_gpu_verify(verify)
    call = (solver._native.solve_argon2id if kind == "argon2id"
            else solver._native.solve_hashx)
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter()
        call("ab" * 64, difficulty, 1, 0.0)
        ts.append((time.perf_counter() - t0) * 1000)
    return statistics.median(ts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--algo", choices=["argon2id", "hashx", "both"],
                    default="argon2id")
    ap.add_argument("--reps", type=int, default=15)
    ap.add_argument("--difficulty", type=int, nargs="+",
                    default=[6, 8, 10])
    args = ap.parse_args()

    solver = AnubisSolver(threads=1)
    lib = solver._native.lib
    print("gpu:", solver.gpu, "| version:", solver.version, flush=True)

    kinds = ["argon2id", "hashx"] if args.algo == "both" else [args.algo]
    for kind in kinds:
        vms = one_verify_ms(lib, kind)
        print(f"\n{kind}: one CPU verify hash = {vms:.2f} ms", flush=True)
        default_d = ([6, 8, 10] if kind == "argon2id" else [24, 26])
        for d in (args.difficulty if args.difficulty != [6, 8, 10]
                  else default_d):
            on = bench(solver, kind, d, args.reps, True)
            off = bench(solver, kind, d, args.reps, False)
            print(f"  d{d:<2} verify {on:9.1f} ms | no-verify {off:9.1f} ms | "
                  f"{on - off:7.1f} ms ({100 * (on - off) / on:5.1f}%)",
                  flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
