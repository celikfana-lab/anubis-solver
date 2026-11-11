#!/usr/bin/env python3
"""
Benchmark solver speed per Anubis challenge tier.

Anubis' docs group the challenge algorithms into light/medium/hard tiers:

    tier    fast/slow   argon2id   sha256   hashx
    light   2           2          8        7
    medium  4           4          16       15
    hard    6           6          24       20

This script runs each tier on one thread and reports the expected work
(16^d hashes for nibble difficulties, 2^d for bit difficulties), the measured
median wall time and the implied hash rate. It also measures thread scaling
for the default `fast` challenge.

    python3 tools/bench_tiers.py [--reps N] [--threads N] [--out results/speed-tiers.json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisSolver  # noqa: E402

TIERS = {
    "fast": [(2, "light"), (4, "medium"), (6, "hard")],
    "slow": [(2, "light"), (4, "medium"), (6, "hard")],
    "sha256": [(8, "light"), (16, "medium"), (24, "hard")],
    "hashx": [(7, "light"), (15, "medium"), (20, "hard")],
    "argon2id": [(2, "light"), (4, "medium"), (6, "hard")],
}


def expected_hashes(algorithm: str, difficulty: int) -> int:
    if algorithm in ("fast", "slow"):
        return 16**difficulty          # leading zero hex nibbles
    return 2**difficulty               # leading zero bits


def solve_once(solver: AnubisSolver, algorithm: str, difficulty: int, threads: int):
    challenge = os.urandom(64).hex()
    if algorithm in ("fast", "slow"):
        return solver._native.solve_nibbles(challenge, difficulty, threads, 0)
    if algorithm == "sha256":
        return solver._native.solve_bits(challenge, difficulty, threads, 0)
    if algorithm == "hashx":
        return solver._native.solve_hashx(challenge, difficulty, threads, 0)
    if algorithm == "argon2id":
        return solver._native.solve_argon2id(challenge, difficulty, threads, 0)
    raise ValueError(algorithm)


def bench_tier(solver: AnubisSolver, algorithm: str, difficulty: int, name: str,
               reps: int, threads: int) -> dict:
    times = []
    nonces = []
    for _ in range(reps):
        nonce, _, ms = solve_once(solver, algorithm, difficulty, threads)
        times.append(ms)
        nonces.append(nonce)
    median = statistics.median(times)
    work = expected_hashes(algorithm, difficulty)
    # Summing the found nonces gives the actual number of candidates tested
    # (each solve starts at 0 and walks upward), which is a far more stable
    # rate estimate than a single geometric solve time.
    total_time = sum(times)
    total_work = sum(max(1, n) for n in nonces)
    rate = total_work / (total_time / 1000.0) if total_time else 0.0
    expected_ms = work / rate * 1000.0 if rate else 0.0
    return {
        "algorithm": algorithm,
        "tier": name,
        "difficulty": difficulty,
        "expected_hashes": work,
        "reps": reps,
        "threads": threads,
        "median_ms": round(median, 2),
        "min_ms": round(min(times), 2),
        "max_ms": round(max(times), 2),
        "expected_ms": round(expected_ms, 2),
        "hashes_per_second": int(rate),
        "total_candidates": total_work,
    }


def bench_threads(solver: AnubisSolver, reps: int) -> list[dict]:
    out = []
    for threads in (1, 2, 4, 8):
        times = []
        for _ in range(reps):
            _, _, ms = solve_once(solver, "fast", 4, threads)
            times.append(ms)
        out.append(
            {
                "threads": threads,
                "median_ms": round(statistics.median(times), 2),
                "min_ms": round(min(times), 2),
            }
        )
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument(
        "--out", default=str(Path(__file__).resolve().parent.parent / "results" / "speed-tiers.json")
    )
    args = parser.parse_args(argv)

    solver = AnubisSolver(threads=args.threads)
    results = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "cpus": os.cpu_count(),
            "avx2_disabled": bool(os.environ.get("ANUBIS_NO_AVX2")),
            "shani_disabled": bool(os.environ.get("ANUBIS_NO_SHANI")),
        },
        "tiers": [],
        "thread_scaling_fast_d4": [],
    }

    print(f"host: {results['host']}")
    print(f"{'algorithm':<9} {'tier':<7} {'d':>2} {'expected':>12} {'E[t]':>9} {'rate':>12}")
    for algorithm, tiers in TIERS.items():
        for difficulty, name in tiers:
            row = bench_tier(solver, algorithm, difficulty, name, args.reps, args.threads)
            results["tiers"].append(row)
            print(
                f"{algorithm:<9} {name:<7} {difficulty:>2} "
                f"{row['expected_hashes']:>12,} {row['expected_ms']:>8.1f}ms "
                f"{row['hashes_per_second']:>11,}/s"
            )

    print("\nthread scaling (fast, difficulty 4):")
    results["thread_scaling_fast_d4"] = bench_threads(solver, max(3, args.reps))
    for row in results["thread_scaling_fast_d4"]:
        print(f"  {row['threads']:>2} threads: {row['median_ms']:>7.1f} ms (min {row['min_ms']:.1f})")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
