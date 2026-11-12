#!/usr/bin/env python3
"""HashX on the GPU (CUDA) vs the CPU.

    python3 tools/bench_hashx_gpu.py                 # CPU
    ANUBIS_GPU_HASHX=1 python3 tools/bench_hashx_gpu.py  # GPU
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisSolver  # noqa: E402


def main() -> int:
    solver = AnubisSolver(threads=1)
    mode = "gpu" if os.environ.get("ANUBIS_GPU_HASHX") else "cpu"
    print("gpu:", solver.gpu, "mode:", mode)
    ch = "ab" * 64
    for d in (24, 26, 28):
        t0 = time.perf_counter()
        n, r, ms = solver._native.solve_hashx(ch, d, 1, 0)
        dt = time.perf_counter() - t0
        print(f"{mode} hashx d{d}: wall {dt*1000:8.1f} ms  reported {ms:8.1f} ms"
              f"  {(n+1)/ms/1e6:7.2f} MH/s (nonce {n})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
