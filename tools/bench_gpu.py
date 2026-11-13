#!/usr/bin/env python3
"""Compare the GPU backends (CUDA, Level Zero, Vulkan, OpenCL) against the CPU.

    python3 tools/bench_gpu.py

Runs the same workloads in subprocesses, once per backend selection, and
prints MH/s. The CPU row disables every GPU path, including OpenCL. Every
digest is checked against hashlib before its number is reported, so a row
that appears here is a row that actually hashed.
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
    modes = [
        ("cuda/l0/vulkan (auto)", {}),
        ("level zero", {"ANUBIS_NO_CUDA": "1", "ANUBIS_NO_VULKAN": "1"}),
        ("vulkan", {"ANUBIS_NO_CUDA": "1", "ANUBIS_NO_LEVELZERO": "1"}),
        ("opencl", {"ANUBIS_OPENCL": "1", "ANUBIS_NO_CUDA": "1",
                    "ANUBIS_NO_VULKAN": "1", "ANUBIS_NO_LEVELZERO": "1"}),
        ("cpu", {"ANUBIS_NO_CUDA": "1", "ANUBIS_NO_VULKAN": "1",
                 "ANUBIS_NO_LEVELZERO": "1", "ANUBIS_NO_OPENCL": "1"}),
    ]
    results = []
    for name, env in modes:
        res = run_mode(env)
        results.append((name, res))
        print(f"{name:<22} -> {res['gpu']}")
    print()
    keys = ("fast d6", "fast d7", "sha256 b24", "sha256 b26")
    header = f"{'workload':<12}" + "".join(f"{n.split(' ')[0][:8]:>10}" for n, _ in results)
    print(header)
    for key in keys:
        row = f"{key:<12}"
        for _, res in results:
            v = res["work"].get(key)
            row += f"{v['mhs']:>10.1f}" if v else f"{'-':>10}"
        print(row)
    print("(numbers are MH/s; GPU names above)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
