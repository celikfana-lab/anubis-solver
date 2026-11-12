#!/usr/bin/env python3
"""Run the AVX2-vs-AVX-512 comparison, for Kaggle/Colab notebooks.

Builds nothing: run `make` first. Then:

    python3 tools/kaggle_avx512.py

It executes `tools/bench_avx512.py` twice, once with native dispatch and once
with ANUBIS_NO_AVX512=1, and prints both results plus the speedup. Each run
verifies every digest against hashlib, so a broken kernel fails instead of
silently looking fast.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "tools" / "bench_avx512.py"


def run(force_avx2: bool) -> tuple[dict[str, float], int]:
    env = dict(os.environ)
    env.pop("ANUBIS_NO_AVX512", None)
    if force_avx2:
        env["ANUBIS_NO_AVX512"] = "1"
    proc = subprocess.run(
        [sys.executable, str(BENCH)], env=env, capture_output=True, text=True
    )
    sys.stdout.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"benchmark failed (exit {proc.returncode})")
    rates = {}
    width = 0
    for line in proc.stdout.splitlines():
        w = re.match(r"^batch width: (\d+)", line)
        if w:
            width = int(w.group(1))
        m = re.match(r"^(fast d6|sha256 b24)\s*:.*?([0-9.]+) MH/s", line)
        if m:
            rates[m.group(1)] = float(m.group(2))
    return rates, width


def main() -> int:
    print("=== native dispatch (AVX-512 when present) ===")
    native, width = run(False)
    print("\n=== forced AVX2 (8-way) ===")
    avx2, _ = run(True)
    if width < 16:
        print("\nNOTE: this host did not select the AVX-512 kernel "
              f"(batch width {width}); the two runs are the same code path.")
    print("\n=== comparison ===")
    print(f"{'workload':<12} {'AVX2':>10} {'AVX-512':>10} {'speedup':>9}")
    for key in ("fast d6", "sha256 b24"):
        a = avx2.get(key)
        n = native.get(key)
        if a and n:
            print(f"{key:<12} {a:>8.2f} M {n:>8.2f} M {n/a:>8.2f}x")
        else:
            print(f"{key:<12} {'n/a':>10} {'n/a':>10}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
