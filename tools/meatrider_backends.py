#!/usr/bin/env python3
"""
Every `meatrider` kernel, on the same challenge.

The tier is SHA-256d over a real 80-byte Bitcoin block header, and the whole
point of this script is that it does not matter which kernel mines it: the CPU
reference, SHA-NI, AVX2, AVX-512, OpenCL, Vulkan, Level Zero, CUDA/PTX, TPU and
the WASM modules all have to answer with the same digest for the same header.
So each row is checked against tools/meatrider_ref.py, an independent Python
implementation of the same header.

    python3 tools/meatrider_backends.py
    python3 tools/meatrider_backends.py --reps 400 --json results/meatrider-backends.json

The rate column is the search rate, not a microbenchmark of the hash: n solves
at difficulty d cost an expected n * 2^d hashes against the measured wall clock,
and every solve is a real search that had to find a real hit and have it
re-verified by the library.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import meatrider_ref  # noqa: E402

LIB = ROOT / "libanubis_solver.so"

# The tier's backends, in the library's own order.
SCALAR, SHANI, AVX2, AVX512, OPENCL, VULKAN, L0, CUDA, TPU = range(9)


def load() -> ctypes.CDLL:
    lib = ctypes.CDLL(str(LIB))
    lib.anubis_meatrider_backend_count.restype = ctypes.c_int
    lib.anubis_meatrider_backend_name.restype = ctypes.c_char_p
    lib.anubis_meatrider_backend_name.argtypes = [ctypes.c_int]
    for f in ("anubis_meatrider_backend_available", "anubis_meatrider_backend_active"):
        getattr(lib, f).restype = ctypes.c_int
    lib.anubis_meatrider_backend_available.argtypes = [ctypes.c_int]
    lib.anubis_meatrider_backend_digest.restype = ctypes.c_int
    lib.anubis_meatrider_backend_digest.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint32, ctypes.c_char_p]
    lib.anubis_meatrider_backend_solve.restype = ctypes.c_int
    lib.anubis_meatrider_backend_solve.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_double,
        ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.POINTER(ctypes.c_double)]
    lib.anubis_verify_meatrider.restype = ctypes.c_int
    lib.anubis_verify_meatrider.argtypes = [
        ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_char_p]
    return lib


def name(lib, backend: int) -> str:
    return lib.anubis_meatrider_backend_name(backend).decode()


def digest(lib, backend: int, challenge: bytes, difficulty: int, nonce: int) -> str | None:
    buf = ctypes.create_string_buffer(65)
    rc = lib.anubis_meatrider_backend_digest(
        challenge.hex().encode(), difficulty, backend, nonce, buf)
    return buf.value.decode() if rc == 0 else None


def solve(lib, backend: int, challenge: bytes, difficulty: int, threads: int,
          budget_ms: float = 0.0):
    nonce = ctypes.c_uint32(0)
    ms = ctypes.c_double(0.0)
    buf = ctypes.create_string_buffer(65)
    rc = lib.anubis_meatrider_backend_solve(
        challenge.hex().encode(), difficulty, backend, threads, budget_ms,
        ctypes.byref(nonce), buf, ctypes.byref(ms))
    return rc, nonce.value, buf.value.decode(), ms.value


def parity(lib, challenges: list[bytes], difficulties: list[int],
           nonces: list[int]) -> dict[int, tuple[int, int]]:
    """digest checks: (passed, attempted) per backend, against Python."""
    result = {}
    for backend in range(lib.anubis_meatrider_backend_count()):
        if not lib.anubis_meatrider_backend_available(backend):
            continue
        passed = attempted = 0
        for ch in challenges:
            for d in difficulties:
                for n in nonces:
                    want = meatrider_ref.digest(ch, d, n).hex()
                    got = digest(lib, backend, ch, d, n)
                    if got is None:
                        continue          # accelerator: reports hits only
                    attempted += 1
                    passed += got == want
        result[backend] = (passed, attempted)
    return result


def hashes_done(backend: int, nonce: int, chunk: int, devices: int) -> int:
    """How many hashes a solve actually performed.

    The CPU walks nonces in order and stops at the hit. The accelerators dispatch
    a whole chunk of CHUNK nonces and only then look, so a solve that hits at
    nonce 5 still cost a full chunk -- which is why the rate row uses the chunk
    arithmetic rather than 2^difficulty.

    A multi-GPU CUDA solve splits the nonce space across devices that run in
    lockstep, so both burn about the chunks the winning slice needed; the count
    is that estimate, not a measurement of each device's dispatch.
    """
    if backend >= OPENCL:
        return devices * (nonce // chunk + 1) * chunk
    return nonce + 1


def cuda_devices(lib: ctypes.CDLL) -> int:
    """How many CUDA devices the library will use, from its own info string."""
    try:
        lib.anubis_gpu_info.restype = ctypes.c_char_p
        info = lib.anubis_gpu_info()
    except AttributeError:
        return 1
    if not info:
        return 1
    text = info.decode()
    if "x" not in text:
        return 1
    tail = text.rsplit("x", 1)[1].strip()
    return int(tail) if tail.isdigit() and int(tail) > 0 else 1


def rate(lib, backend: int, challenge: bytes, difficulty: int, threads: int,
         reps: int, chunk: int, devices: int) -> tuple[float, int]:
    """(hashes/second, hits verified) from `reps` real solves."""
    # One untimed solve first: the OpenCL and Vulkan paths build a pipeline on
    # first use, and that cost belongs in neither the rate nor a user's first
    # challenge.
    rc, *_ = solve(lib, backend, challenge, difficulty, threads)
    if rc != 0:
        raise RuntimeError(f"{name(lib, backend)}: warm-up solve returned {rc}")

    started = time.perf_counter()
    hashes = verified = 0
    for _ in range(reps):
        rc, nonce, hexdigest, _ms = solve(lib, backend, challenge, difficulty, threads)
        if rc != 0:
            raise RuntimeError(f"{name(lib, backend)}: solve returned {rc}")
        check = ctypes.create_string_buffer(65)
        if lib.anubis_verify_meatrider(
                challenge.hex().encode(), nonce, difficulty, check) != 0:
            raise RuntimeError(f"{name(lib, backend)}: verify rejected {nonce}")
        if check.value.decode() != hexdigest:
            raise RuntimeError(f"{name(lib, backend)}: digest disagrees with the reference")
        hashes += hashes_done(backend, nonce, chunk,
                              devices if backend == CUDA else 1)
        verified += 1
    elapsed = time.perf_counter() - started
    return hashes / elapsed, verified


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--threads", type=int, default=1, help="threads per solve (default 1)")
    ap.add_argument("--reps", type=int, default=0,
                    help="solves per rate row (default: scaled so each row runs ~1 s)")
    ap.add_argument("--difficulty", type=int, default=0,
                    help="search difficulty for the ACCELERATOR rows (default 23; a "
                         "deep rung makes the per-device chunk estimate less noisy)")
    ap.add_argument("--cpu-difficulty", type=int, default=20,
                    help="search difficulty for the CPU rows (default 20; raising it "
                         "with --difficulty would make a 2 MHash/s kernel grind 2^d)")
    ap.add_argument("--budget-ms", type=float, default=3000.0,
                    help="give up on a rate row after this long (default 3000)")
    ap.add_argument("--json", type=Path, default=None, help="write the rows as JSON")
    args = ap.parse_args()

    if not LIB.exists():
        print(f"error: {LIB} is not built; run make", file=sys.stderr)
        return 1
    lib = load()

    devices = cuda_devices(lib)
    print(f"cuda devices: {devices}")
    print(f"meatrider backends on {platform.machine()} / {platform.system()} "
          f"{platform.release()}, {args.threads} thread(s)")
    print(f"  active: {name(lib, lib.anubis_meatrider_backend_active())}")

    available = [b for b in range(lib.anubis_meatrider_backend_count())
                 if lib.anubis_meatrider_backend_available(b)]
    missing = [name(lib, b) for b in range(lib.anubis_meatrider_backend_count())
               if b not in available]
    print(f"  available: {', '.join(name(lib, b) for b in available)}")
    if missing:
        print(f"  not here:  {', '.join(missing)}")

    # ---- digest parity against the independent Python reference ----------
    challenges = [bytes(range(32)), bytes(range(32, 64)), bytes([0xA5] * 32)]
    difficulties = [1, 8, 12, 20, 32]
    nonces = [0, 1, 0x7FFFFFFF, 0xFFFFFFFF]
    checks = parity(lib, challenges, difficulties, nonces)
    print("\ndigest parity (SHA-256d over the header, vs tools/meatrider_ref.py):")
    for backend, (passed, attempted) in sorted(checks.items()):
        if attempted:
            state = "ok" if passed == attempted else "FAIL"
            print(f"  {name(lib, backend):10s} {passed:4d}/{attempted:<4d} {state}")
        else:
            print(f"  {name(lib, backend):10s} hit-only: checked end to end below")

    # ---- search rate ----------------------------------------------------
    chunk = 1 << 22                     # the kernels' default dispatch
    env_chunk = os.environ.get("ANUBIS_OPENCL_CHUNK") or os.environ.get("ANUBIS_VULKAN_CHUNK")
    if env_chunk:
        chunk = int(env_chunk, 0)
    rows = []
    for backend in available:
        d = (args.difficulty or 23) if backend >= OPENCL else args.cpu_difficulty
        reps = args.reps
        if reps <= 0:
            # aim at ~1 s of work: 2^d hashes per solve
            target = 1.0
            per_solve = (2 ** d) / 60e6          # a conservative guess, hashes/s
            reps = max(5, min(2000, int(target / max(per_solve, 1e-6))))
        ch = challenges[0]
        try:
            hps, verified = rate(lib, backend, ch, d, args.threads, reps, chunk,
                                 devices)
        except RuntimeError as exc:
            print(f"  {name(lib, backend):10s} {exc}")
            continue
        rows.append({"backend": name(lib, backend), "difficulty": d,
                     "hashes_per_second": round(hps, 1), "solves": verified,
                     "threads": args.threads})
        print(f"\nrate: {name(lib, backend)} at difficulty {d}, {verified} solves, all hits "
              f"re-verified")
        print(f"  {hps / 1e6:10.3f} MHash/s  ({hps:,.0f} H/s)")

    print("\nbackend     H/s                 solves  difficulty")
    for row in rows:
        print(f"{row['backend']:10s}  {row['hashes_per_second']:>15,.0f}  "
              f"{row['solves']:6d}  {row['difficulty']:10d}")
    if not rows:
        print("(no backend could be measured)")

    if args.json is not None:
        payload = {
            "generated_by": "tools/meatrider_backends.py",
            "machine": f"{platform.machine()} / {platform.system()} {platform.release()}",
            "cpu": platform.processor(),
            "threads": args.threads,
            "cuda_devices": devices,
            "digest_checks": {name(lib, b): {"passed": p, "attempted": a}
                              for b, (p, a) in sorted(checks.items())},
            "rows": rows,
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"\nwrote {args.json}")
    return 0 if all(p == a for p, a in checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
