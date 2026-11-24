#!/usr/bin/env python3
"""
Every `meatrider` kernel has to answer with the same digest.

The tier is SHA-256d over a real 80-byte Bitcoin block header, and the library
carries it as one portable C reference plus a kernel per accelerator. A proof
must not depend on which one produced it, so this test walks the whole
inventory:

  * the inventory itself (every backend has a name, an availability answer, and
    a pin that the library honours);
  * digest parity for the kernels that report a digest, against
    tools/meatrider_ref.py -- an independent Python implementation of the same
    header, not a second C call;
  * a real search on every available kernel, with the winning nonce re-checked
    by anubis_verify_meatrider and its digest compared with the reference.

    python3 tests/test_meatrider_backends.py
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import meatrider_ref  # noqa: E402

LIB = ROOT / "libanubis_solver.so"

EXPECTED_NAMES = ["cpu", "shani", "avx2", "avx512", "opencl", "vulkan",
                  "levelzero", "cuda", "tpu"]

CHALLENGES = [bytes(range(32)), bytes(range(32, 64)), bytes([0x5A] * 32)]
DIFFICULTIES = [1, 8, 12, 20, 32]
NONCES = [0, 1, 0x7FFFFFFF, 0xFFFFFFFF]

passed = failed = 0


def check(ok: bool, what: str) -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok   {what}")
    else:
        failed += 1
        print(f"  FAIL {what}")


def load() -> ctypes.CDLL:
    lib = ctypes.CDLL(str(LIB))
    lib.anubis_meatrider_backend_count.restype = ctypes.c_int
    lib.anubis_meatrider_backend_name.restype = ctypes.c_char_p
    lib.anubis_meatrider_backend_name.argtypes = [ctypes.c_int]
    lib.anubis_meatrider_backend_available.restype = ctypes.c_int
    lib.anubis_meatrider_backend_available.argtypes = [ctypes.c_int]
    lib.anubis_meatrider_backend_active.restype = ctypes.c_int
    lib.anubis_meatrider_backend_digest.restype = ctypes.c_int
    lib.anubis_meatrider_backend_digest.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint32,
        ctypes.c_char_p]
    lib.anubis_meatrider_backend_solve.restype = ctypes.c_int
    lib.anubis_meatrider_backend_solve.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        ctypes.c_double, ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_double)]
    lib.anubis_verify_meatrider.restype = ctypes.c_int
    lib.anubis_verify_meatrider.argtypes = [
        ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_char_p]
    return lib


def digest(lib, backend: int, challenge: bytes, difficulty: int, nonce: int):
    buf = ctypes.create_string_buffer(65)
    rc = lib.anubis_meatrider_backend_digest(challenge.hex().encode(),
                                             difficulty, backend, nonce, buf)
    return buf.value.decode() if rc == 0 else None


def solve(lib, backend: int, challenge: bytes, difficulty: int, budget_ms: float):
    nonce = ctypes.c_uint32(0)
    ms = ctypes.c_double(0.0)
    buf = ctypes.create_string_buffer(65)
    rc = lib.anubis_meatrider_backend_solve(challenge.hex().encode(), difficulty,
                                            backend, 1, budget_ms,
                                            ctypes.byref(nonce), buf,
                                            ctypes.byref(ms))
    return rc, nonce.value, buf.value.decode(), ms.value


def main() -> int:
    if not LIB.exists():
        print(f"error: {LIB} is not built; run make", file=sys.stderr)
        return 1
    lib = load()

    print("the inventory")
    names = [lib.anubis_meatrider_backend_name(b).decode()
             for b in range(lib.anubis_meatrider_backend_count())]
    check(names == EXPECTED_NAMES, f"nine backends, in order: {', '.join(names)}")
    avail = [b for b in range(len(names))
             if lib.anubis_meatrider_backend_available(b)]
    check(0 in avail, "the portable kernel is always available")
    check(lib.anubis_meatrider_backend_available(-1) == 0,
          "an id outside the list is not available")
    check(lib.anubis_meatrider_backend_name(99) is None,
          "an id outside the list has no name")
    check(lib.anubis_meatrider_backend_active() in avail,
          f"the active kernel ({names[lib.anubis_meatrider_backend_active()]}) is available")

    print("digest parity, against tools/meatrider_ref.py")
    for backend in avail:
        bad = 0
        tried = 0
        for ch in CHALLENGES:
            for d in DIFFICULTIES:
                for n in NONCES:
                    got = digest(lib, backend, ch, d, n)
                    if got is None:
                        continue
                    tried += 1
                    if got != meatrider_ref.digest(ch, d, n).hex():
                        bad += 1
        if tried == 0:
            check(True, f"{names[backend]}: reports hits only, checked by a search below")
        else:
            check(bad == 0, f"{names[backend]}: {tried} digests, {bad} wrong")

    print("a real search on every available kernel")
    ch = CHALLENGES[0]
    for backend in avail:
        d = 14
        rc, nonce, hexdigest, ms = solve(lib, backend, ch, d, 5000.0)
        ok = rc == 0
        if ok:
            check_hex = ctypes.create_string_buffer(65)
            ok = lib.anubis_verify_meatrider(ch.hex().encode(), nonce, d,
                                             check_hex) == 0
            ok = ok and check_hex.value.decode() == hexdigest
            ok = ok and hexdigest == meatrider_ref.digest(ch, d, nonce).hex()
            ok = ok and meatrider_ref.leading_zero_bits(bytes.fromhex(hexdigest)) >= d
        check(ok, f"{names[backend]}: solved 2^{d} in {ms:.0f} ms "
                  f"(nonce {nonce}) and the reference agrees")

    print("the pin agrees with the inventory")
    saved = os.environ.get("ANUBIS_MEATRIDER_BACKEND")
    try:
        os.environ["ANUBIS_MEATRIDER_BACKEND"] = "cpu"
        check(lib.anubis_meatrider_backend_active() == 0,
              "ANUBIS_MEATRIDER_BACKEND=cpu pins the CPU kernel")
        os.environ["ANUBIS_MEATRIDER_BACKEND"] = "no-such-kernel"
        check(lib.anubis_meatrider_backend_active() in avail,
              "an unknown pin falls back to an available kernel instead of failing")
        if 1 in avail:
            os.environ["ANUBIS_MEATRIDER_BACKEND"] = "shani"
            check(lib.anubis_meatrider_backend_active() == 1,
                  "ANUBIS_MEATRIDER_BACKEND=shani pins the SHA-NI kernel")
    finally:
        if saved is None:
            os.environ.pop("ANUBIS_MEATRIDER_BACKEND", None)
        else:
            os.environ["ANUBIS_MEATRIDER_BACKEND"] = saved

    print("bad arguments are refused, not crashed on")
    nonce = ctypes.c_uint32(0)
    buf = ctypes.create_string_buffer(65)
    ms = ctypes.c_double(0.0)
    check(lib.anubis_meatrider_backend_solve(b"", 12, 0, 1, 0.0,
                                             ctypes.byref(nonce), buf,
                                             ctypes.byref(ms)) != 0,
          "an empty challenge is an error")
    check(lib.anubis_meatrider_backend_solve(ch.hex().encode(), 0, 0, 1, 0.0,
                                             ctypes.byref(nonce), buf,
                                             ctypes.byref(ms)) != 0,
          "difficulty 0 is an error")
    check(lib.anubis_meatrider_backend_digest(ch.hex().encode(), 12, 0, 5,
                                              None) != 0,
          "a NULL hex buffer is an error")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
