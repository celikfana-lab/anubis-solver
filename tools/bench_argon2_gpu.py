#!/usr/bin/env python3
"""Argon2id GPU experiment: correctness against argon2-cffi, speed vs CPU.

    python3 tools/bench_argon2_gpu.py                 # CPU only
    ANUBIS_GPU_ARGON2=1 python3 tools/bench_argon2_gpu.py   # GPU path
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisSolver  # noqa: E402

CH = "ab" * 64
RAW = bytes.fromhex(CH)
USE_LE = RAW[-1] >= 0x80


def main() -> int:
    solver = AnubisSolver(threads=1)
    print("gpu:", solver.gpu)

    lib = solver._native.lib
    lib.anubis_cuda_argon2_digest.restype = ctypes.c_int
    lib.anubis_cuda_argon2_digest.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint32,
        ctypes.c_char_p,
    ]
    buf = ctypes.create_string_buffer(32)
    nonce = 12345
    rc = lib.anubis_cuda_argon2_digest(RAW, len(RAW), 1 if USE_LE else 0,
                                       nonce, buf)
    print("gpu digest rc:", rc)
    if rc == 0:
        try:
            from argon2.low_level import Type, hash_secret_raw
            want = hash_secret_raw(
                RAW, nonce.to_bytes(8, "little" if USE_LE else "big"),
                time_cost=2, memory_cost=19456, parallelism=1, hash_len=32,
                type=Type.ID)
            print("gpu digest ok:", want == buf.raw)
        except ImportError:
            print("gpu digest:", buf.raw.hex())

    mode = "gpu" if os.environ.get("ANUBIS_GPU_ARGON2") else "cpu"
    for d in (4, 6):
        t0 = time.perf_counter()
        n, r, _ = solver._native.solve_argon2id(CH, d, 1, 0)
        dt = time.perf_counter() - t0
        print(f"{mode} d{d}: {dt*1000:8.0f} ms  {2**d/dt:8.1f} h/s  (nonce {n})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
