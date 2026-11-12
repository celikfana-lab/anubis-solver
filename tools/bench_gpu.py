#!/usr/bin/env python3
"""Compare the GPU backend (CUDA if built, else Vulkan) against the CPU.

    python3 tools/bench_gpu.py

Runs the same workloads twice in subprocesses: once with the GPU enabled and
once with ANUBIS_NO_CUDA=1 ANUBIS_NO_VULKAN=1. Every digest is checked
against hashlib.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def worker() -> int:
    sys.path.insert(0, str(ROOT))
    from anubis_solver import AnubisSolver

    solver = AnubisSolver(threads=1)
    ch = "ab" * 64
    out = {"gpu": solver.gpu, "cpu_threads": solver.threads, "work": {}}

    def run_fast(d: int) -> None:
        t0 = time.perf_counter()
        n, r, _ = solver._native.solve_nibbles(ch, d, 1, 0)
        dt = time.perf_counter() - t0
        if hashlib.sha256((ch + str(n)).encode()).hexdigest() != r:
            raise SystemExit("fast digest mismatch")
        out["work"][f"fast d{d}"] = {"sec": dt, "mhs": n / dt / 1e6}

    def run_bits(d: int) -> None:
        chh = "cd" * 64
        raw = bytes.fromhex(chh)
        use_le = raw[-1] >= 0x80
        t0 = time.perf_counter()
        n, r, _ = solver._native.solve_bits(chh, d, 1, 0)
        dt = time.perf_counter() - t0
        want = hashlib.sha256(raw + n.to_bytes(4, "little" if use_le else "big")).hexdigest()
        if want != r:
            raise SystemExit("sha256 digest mismatch")
        out["work"][f"sha256 b{d}"] = {"sec": dt, "mhs": n / dt / 1e6}

    run_fast(6)
    run_fast(7)
    run_bits(24)
    run_bits(26)
    print("RESULT " + json.dumps(out), flush=True)
    return 0


def run_mode(env_extra: dict[str, str]) -> dict:
    env = dict(os.environ)
    for key in ("ANUBIS_NO_CUDA", "ANUBIS_NO_VULKAN"):
        env.pop(key, None)
    env.update(env_extra)
    proc = subprocess.run([sys.executable, __file__, "--worker"], env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit("worker failed")
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    raise SystemExit("no result")


def main() -> int:
    if "--worker" in sys.argv:
        return worker()
    gpu = run_mode({})
    cpu = run_mode({"ANUBIS_NO_CUDA": "1", "ANUBIS_NO_VULKAN": "1"})
    print(f"GPU backend : {gpu['gpu']}")
    print(f"CPU threads : {gpu['cpu_threads']}")
    print()
    print(f"{'workload':<12}{'GPU':>12}{'CPU':>12}{'speedup':>10}")
    for key in ("fast d6", "fast d7", "sha256 b24", "sha256 b26"):
        g = gpu["work"].get(key)
        c = cpu["work"].get(key)
        if not g or not c:
            continue
        print(f"{key:<12}{g['mhs']:>9.1f} M/s{c['mhs']:>9.1f} M/s"
              f"{g['mhs']/c['mhs']:>9.1f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
