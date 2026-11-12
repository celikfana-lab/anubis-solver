#!/usr/bin/env python3
"""Compare every SHA-256 backend the solver has, on the current machine.

    python3 tools/bench_isa.py

Each row runs in its own process because the dispatch caches its choice on
first use. Modes, fastest to slowest expected: AVX-512 16-way, AVX2 8-way,
SHA-NI single block, portable C. Digests are verified against hashlib in
tools/bench_avx512.py, which this script drives.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "tools" / "bench_avx512.py"

MODES = [
    ("AVX-512 16-way", {}),
    ("AVX2 8-way", {"ANUBIS_NO_AVX512": "1"}),
    ("SHA-NI scalar", {"ANUBIS_NO_AVX512": "1", "ANUBIS_NO_AVX2": "1"}),
    ("portable C", {"ANUBIS_NO_AVX512": "1", "ANUBIS_NO_AVX2": "1",
                    "ANUBIS_NO_SHANI": "1"}),
]


def bench(extra: dict[str, str]) -> tuple[int, dict[str, float]]:
    env = dict(os.environ)
    for key in ("ANUBIS_NO_AVX512", "ANUBIS_NO_AVX2", "ANUBIS_NO_SHANI"):
        env.pop(key, None)
    env.update(extra)
    proc = subprocess.run([sys.executable, str(BENCH)], env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"bench failed: {proc.returncode}")
    width = 0
    rates: dict[str, float] = {}
    for line in proc.stdout.splitlines():
        m = re.match(r"^batch width: (\d+)", line)
        if m:
            width = int(m.group(1))
        m = re.match(r"^(fast d6|sha256 b24)\s*:.*?([0-9.]+) MH/s", line)
        if m:
            rates[m.group(1)] = float(m.group(2))
    return width, rates


def main() -> int:
    rows = []
    for name, extra in MODES:
        print(f"running {name} ...", flush=True)
        width, rates = bench(extra)
        rows.append((name, width, rates.get("fast d6", 0.0),
                     rates.get("sha256 b24", 0.0)))
    print()
    print(f"{'backend':<16}{'width':>6}{'fast d6':>12}{'sha256 b24':>13}")
    for name, width, fast, bits in rows:
        print(f"{name:<16}{width:>6}{fast:>10.2f} M{bits:>11.2f} M")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
