#!/usr/bin/env python3
"""Benchmark the library's GPU path with the GPU clock state in view.

A small iGPU clocks itself: it idles at 300 MHz and only climbs to its boost
clock (1400 MHz on the Iris Xe here) under sustained load. That means a
short benchmark measures the ramp, not the hardware. This tool reports both,
and shows what the boost pin does or does not do.

    python3 tools/bench_gpu_boost.py                # opencl backend, 14 solves
    python3 tools/bench_gpu_boost.py --iters 30 --difficulty 24
    ANUBIS_GPU_BOOST=1 python3 tools/bench_gpu_boost.py   # ask for the pin

What it prints: the GPU's power state, whether the clock floor could be
pinned (it needs write access to /sys/class/drm/cardN/gt_min_freq_mhz), then
one row per solve: elapsed, MH/s, and the clock before and after. The first
row is cold, the last rows are the steady state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def worker(args: argparse.Namespace) -> int:
    from anubis_solver import AnubisSolver

    solver = AnubisSolver(threads=1)
    chh = "cd" * 64
    raw = bytes.fromhex(chh)
    use_le = raw[-1] >= 0x80

    stop = threading.Event()
    samples: list[tuple[float, int]] = []

    def sampler() -> None:
        while not stop.is_set():
            samples.append((time.perf_counter(), solver.gpu_freq_mhz()))
            time.sleep(0.005)

    # One untimed solve first: it compiles the OpenCL program, and that cost
    # must not be mistaken for the clock ramp.
    solver._native.solve_bits(chh, 17, 1, 0)

    time.sleep(args.idle)

    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    rows = []
    for i in range(args.iters):
        before = len(samples)
        t0 = time.perf_counter()
        nonce, response, _ = solver._native.solve_bits(chh, args.difficulty, 1, 0)
        dt = time.perf_counter() - t0
        after = len(samples)
        want = hashlib.sha256(
            raw + nonce.to_bytes(4, "little" if use_le else "big")
        ).hexdigest()
        if want != response:
            print("digest mismatch", file=sys.stderr)
            return 1
        window = [mhz for _, mhz in samples[before:after]] or [solver.gpu_freq_mhz()]
        rows.append(
            {
                "iter": i,
                "nonce": nonce,
                "sec": dt,
                "mhs": nonce / dt / 1e6,
                "mhz_min": min(window),
                "mhz_max": max(window),
            }
        )
    stop.set()
    th.join(timeout=1.0)
    print(
        "RESULT "
        + json.dumps(
            {"rows": rows, "kernel": solver.active_kernel(),
             "gpu": solver.gpu, "state": solver.gpu_power_state()}
        ),
        flush=True,
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=14)
    ap.add_argument("--difficulty", type=int, default=24)
    ap.add_argument("--idle", type=float, default=1.5,
                    help="seconds of idle before the first timed solve")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.worker:
        return worker(args)

    from anubis_solver import AnubisSolver

    probe = AnubisSolver(threads=1)
    state = probe.gpu_power_state()
    print("GPU power state")
    for key in ("card", "profile", "cur_mhz", "act_mhz", "min_mhz", "max_mhz",
                "boost_mhz", "rp0_mhz", "rpn_mhz", "writable", "boost"):
        print(f"  {key:<10} {state.get(key)}")
    rc = probe.gpu_boost(True)
    can_pin = rc == 0
    if can_pin:
        print("  boost      pinned: the floor is at the boost clock")
    else:
        print("  boost      not permitted (sysfs is root-only); "
              "ANUBIS_GPU_BOOST=1 will retry at load")
    probe.gpu_boost(False)

    base_env = dict(os.environ)
    base_env.update({
        "ANUBIS_OPENCL": "1",
        "ANUBIS_NO_CUDA": "1",
        "ANUBIS_NO_VULKAN": "1",
        "ANUBIS_NO_LEVELZERO": "1",
    })

    runs = [("unpinned", "0")]
    if can_pin:
        runs.append(("pinned", "1"))

    results = []
    for label, boost_env in runs:
        env = dict(base_env)
        env["ANUBIS_GPU_BOOST"] = boost_env
        proc = subprocess.run([sys.executable, __file__, "--worker",
                               "--iters", str(args.iters),
                               "--difficulty", str(args.difficulty),
                               "--idle", str(args.idle)],
                              env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            return 1
        payload = None
        for line in proc.stdout.splitlines():
            if line.startswith("RESULT "):
                payload = json.loads(line[7:])
        if payload is None:
            print("no result", file=sys.stderr)
            return 1
        results.append((label, payload))

    for label, payload in results:
        rows = payload["rows"]
        print()
        print(f"[{label}] kernel: {payload['kernel']}   gpu: {payload['gpu']}   "
              f"difficulty {args.difficulty}")
        print(f"{'iter':>4} {'elapsed ms':>11} {'MH/s':>8} {'MHz min':>8} "
              f"{'MHz max':>8}")
        for r in rows:
            print(f"{r['iter']:>4} {r['sec'] * 1e3:>11.1f} {r['mhs']:>8.1f} "
                  f"{r['mhz_min']:>8} {r['mhz_max']:>8}")
        steady = rows[len(rows) // 2:]
        cold = rows[0]["mhs"]
        warm = statistics.median(r["mhs"] for r in steady)
        print(f"[{label}] cold {cold:7.1f} MH/s -> steady {warm:7.1f} MH/s "
              f"({warm / cold:.2f}x)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
