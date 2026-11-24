#!/usr/bin/env python3
"""
Run src/meatrider/meatrider.ptx on a real GPU and check it against the reference.

The PTX kernel had only ever been executed by the Python simulator
(test_meatrider_ptx.py). This drives it on hardware through the CUDA driver,
which JITs the checked-in PTX directly -- no nvcc, no ptxas, no cubin:

    python3 src/meatrider/test_meatrider_ptx_gpu.py

It builds meatrider_ptx_loader.c with cc, asks the library's own reference for
the header half (meatrider_ctx_init) and for every digest (meatrider_digest), and
compares:

  * a difficulty-0 dispatch, where every nonce is a "hit", so the (nonce, digest)
    pairs the kernel writes have to match the reference one for one;
  * real searches at increasing difficulty, where the winning nonce is re-derived
    and then timed.

The rate is reported as nonces actually dispatched, not 2^difficulty, so the
number is comparable with tools/meatrider_backends.py.

Exit code is the check count's friend: 0 when everything agreed.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PTX = ROOT / "src" / "meatrider" / "meatrider.ptx"
LOADER_C = ROOT / "src" / "meatrider" / "meatrider_ptx_loader.c"
LOADER = Path("/tmp/libmeatrider_ptx_loader.so")
LIB = ROOT / "libanubis_solver.so"

sys.path.insert(0, str(ROOT / "tools"))
import meatrider_ref  # noqa: E402

passed = failed = 0


def check(ok: bool, what: str) -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok   {what}")
    else:
        failed += 1
        print(f"  FAIL {what}")


class Ctx(ctypes.Structure):
    """meatrider_ctx from src/meatrider/meatrider.h."""

    _fields_ = [
        ("first", ctypes.c_uint8 * 64),
        ("mid", ctypes.c_uint32 * 8),
        ("bits", ctypes.c_uint32),
        ("difficulty", ctypes.c_int),
        ("tail", ctypes.c_uint8 * 12),
        ("tail_block", ctypes.c_uint8 * 64),
    ]


def build_loader() -> None:
    cmd = ["cc", "-O2", "-shared", "-fPIC", "-o", str(LOADER), str(LOADER_C), "-ldl"]
    print("$ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit("the loader did not build")
    if proc.stderr.strip():
        print(proc.stderr.strip(), flush=True)


def load() -> tuple[ctypes.CDLL, ctypes.CDLL]:
    lib = ctypes.CDLL(str(LIB))
    lib.meatrider_ctx_init.restype = ctypes.c_int
    lib.meatrider_ctx_init.argtypes = [ctypes.POINTER(Ctx), ctypes.c_char_p, ctypes.c_int]
    ptx = ctypes.CDLL(str(LOADER))
    ptx.anubis_meatrider_ptx_available.restype = ctypes.c_int
    ptx.anubis_meatrider_ptx_info.restype = ctypes.c_char_p
    ptx.anubis_meatrider_ptx_solve.restype = ctypes.c_int
    ptx.anubis_meatrider_ptx_solve.argtypes = [
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_double,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_int)]
    return lib, ptx


def words_to_hex(words) -> str:
    return "".join(f"{w:08x}" for w in words)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reps", type=int, default=5, help="solves per timed difficulty")
    ap.add_argument("--no-build", action="store_true", help="use the loader as built")
    args = ap.parse_args()

    if not (PTX.exists() and LIB.exists()):
        print("error: build the library (make) and the PTX first", file=sys.stderr)
        return 1
    if not args.no_build:
        build_loader()

    lib, ptx = load()
    if not ptx.anubis_meatrider_ptx_available():
        print("no CUDA driver, or the PTX did not load", file=sys.stderr)
        return 1
    print(f"device: {(ptx.anubis_meatrider_ptx_info() or b'').decode()}")
    print(f"ptx:    {PTX.relative_to(ROOT)} ({PTX.stat().st_size:,} bytes, JITed by the driver)")
    chunk = int(os.environ.get("ANUBIS_PTX_CHUNK", 1 << 22))

    # ---- the digest for every nonce the kernel reports at difficulty 0 -------
    print("\ndigest parity (difficulty 0 makes every nonce a hit):")
    for rd in (bytes(range(32)), bytes(range(32, 64))):
        ctx = Ctx()
        if lib.meatrider_ctx_init(ctypes.byref(ctx), rd, 1) != 0:
            check(False, "meatrider_ctx_init refused a 32-byte challenge")
            continue
        tail = (ctypes.c_uint32 * 3)(*[int.from_bytes(bytes(ctx.tail[4 * i:4 * i + 4]), "little")
                                       for i in range(3)])
        nonce = ctypes.c_uint32(0)
        hashes = (ctypes.c_uint32 * 8)()
        dispatches = ctypes.c_int(0)
        rc = ptx.anubis_meatrider_ptx_solve(ctx.mid, tail, 0, 0, 64, 0.0,
                                            ctypes.byref(nonce), hashes,
                                            ctypes.byref(dispatches))
        got = words_to_hex(list(hashes))
        want = meatrider_ref.digest(rd, 1, nonce.value).hex() if rc == 0 else ""
        check(rc == 0 and got == want,
              f"first hit at nonce {nonce.value}: {got[:16]}… == reference")

    # a sweep: 64 nonces at difficulty 0, each reported digest checked
    rd = bytes(range(32))
    ctx = Ctx()
    lib.meatrider_ctx_init(ctypes.byref(ctx), rd, 1)
    tail = (ctypes.c_uint32 * 3)(*[int.from_bytes(bytes(ctx.tail[4 * i:4 * i + 4]), "little")
                                   for i in range(3)])
    bad = 0
    for base in (0, 1, 1000, 0xFFFF0000):
        nonce = ctypes.c_uint32(0)
        hashes = (ctypes.c_uint32 * 8)()
        rc = ptx.anubis_meatrider_ptx_solve(ctx.mid, tail, 0, base, 64, 0.0,
                                            ctypes.byref(nonce), hashes, None)
        if rc != 0:
            bad += 1
            continue
        if words_to_hex(list(hashes)) != meatrider_ref.digest(rd, 1, nonce.value).hex():
            bad += 1
    check(bad == 0, "4 bases x 64 nonces: every reported digest matches")

    # ---- real searches, with the winning nonce re-derived -------------------
    print("\nreal searches:")
    rows = []
    for difficulty in (16, 20, 24):
        # The header carries nBits, so a proof is bound to its difficulty: the
        # context has to be built for the rung being searched.
        ctx_d = Ctx()
        lib.meatrider_ctx_init(ctypes.byref(ctx_d), rd, difficulty)
        tail_d = (ctypes.c_uint32 * 3)(
            *[int.from_bytes(bytes(ctx_d.tail[4 * i:4 * i + 4]), "little") for i in range(3)])
        total_hashes = 0
        total_dispatches = 0
        started = time.perf_counter()
        for _ in range(args.reps):
            nonce = ctypes.c_uint32(0)
            hashes = (ctypes.c_uint32 * 8)()
            dispatches = ctypes.c_int(0)
            rc = ptx.anubis_meatrider_ptx_solve(ctx_d.mid, tail_d, difficulty, 0, 0,
                                                5000.0, ctypes.byref(nonce),
                                                hashes, ctypes.byref(dispatches))
            if rc != 0:
                check(False, f"difficulty {difficulty}: solve returned {rc}")
                break
            got = words_to_hex(list(hashes))
            want = meatrider_ref.digest(rd, difficulty, nonce.value).hex()
            # Exact, not estimated: the loader reports how many chunk dispatches
            # the winning device issued, and every dispatch is a full chunk.
            total_hashes += max(1, dispatches.value) * chunk
            total_dispatches += dispatches.value
            if got != want:
                check(False, f"difficulty {difficulty}: nonce {nonce.value} digest {got[:16]} != reference")
                break
        else:
            elapsed = time.perf_counter() - started
            hps = total_hashes / elapsed
            rows.append((difficulty, hps))
            print(f"       {dispatches.value} dispatches on the winning device, "
                  f"{elapsed / args.reps * 1000.0:.1f} ms per solve")
            check(True, f"difficulty {difficulty}: {args.reps} solves, "
                        f"{total_hashes:,} nonces, {hps / 1e6:.1f} MHash/s, digests agree")

    print("\nbackend     H/s                 difficulty")
    for difficulty, hps in rows:
        print(f"ptx        {hps:>15,.0f}  {difficulty}")
    if rows:
        med = statistics.median(h for _, h in rows)
        print(f"\nptx median: {med / 1e6:.1f} MHash/s  "
              f"(compare `cuda` from tools/meatrider_backends.py on the same box)")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
