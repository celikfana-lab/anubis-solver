#!/usr/bin/env python3
"""Compare the 8-way AVX2 and 16-way AVX-512 SHA-256 batch paths.

Run it twice on a machine with AVX-512:

    python3 tools/bench_avx512.py                     # native dispatch
    ANUBIS_NO_AVX512=1 python3 tools/bench_avx512.py  # force AVX2

It also prints the batch width the library selected and the CPU flags, and
verifies each solved digest against hashlib (so a wrong kernel fails loudly
instead of just running fast).
"""

from __future__ import annotations

import hashlib
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Compare the CPU kernels only: keep the Vulkan backend out of the way.
os.environ.setdefault("ANUBIS_NO_VULKAN", "1")
os.environ.setdefault("ANUBIS_NO_CUDA", "1")

from anubis_solver import AnubisSolver  # noqa: E402


def cpu_flags() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("flags"):
                    return " ".join(
                        sorted({f for f in line.split(":", 1)[1].split() if "avx512" in f})
                    )
    except OSError:
        pass
    return "?"


def bench_fast(challenge: str, difficulty: int, reps: int) -> tuple[float, int]:
    solver = AnubisSolver(threads=1)
    times = []
    nonce = 0
    for _ in range(reps):
        t0 = time.perf_counter()
        nonce, resp, _ = solver._native.solve_nibbles(challenge, difficulty, 1, 0)
        times.append(time.perf_counter() - t0)
        want = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()
        if want != resp or not resp.startswith("0" * difficulty):
            raise SystemExit(f"fast digest mismatch at nonce {nonce}")
    return statistics.median(times), nonce


def bench_bits(challenge: str, difficulty: int, reps: int) -> tuple[float, int]:
    solver = AnubisSolver(threads=1)
    raw = bytes.fromhex(challenge)
    use_le = raw[-1] >= 0x80
    times = []
    nonce = 0
    for _ in range(reps):
        t0 = time.perf_counter()
        nonce, resp, _ = solver._native.solve_bits(challenge, difficulty, 1, 0)
        times.append(time.perf_counter() - t0)
        msg = raw + nonce.to_bytes(4, "little" if use_le else "big")
        want = hashlib.sha256(msg).hexdigest()
        if want != resp or (int(want, 16) >> (256 - difficulty)) != 0:
            raise SystemExit(f"sha256 digest mismatch at nonce {nonce}")
    return statistics.median(times), nonce


def main() -> int:
    solver = AnubisSolver(threads=1)
    print(f"batch width: {solver.batch_width}  (16=AVX-512, 8=AVX2, 0=scalar)")
    print(f"avx512 flags: {cpu_flags()}  (Vulkan disabled)")
    ch = "ab" * 64
    med, nonce = bench_fast(ch, 6, 5)
    print(f"fast d6     : {med*1000:8.1f} ms  {nonce/med/1e6:7.2f} MH/s")
    med, nonce = bench_bits("cd" * 64, 24, 3)
    print(f"sha256 b24  : {med*1000:8.1f} ms  {nonce/med/1e6:7.2f} MH/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
