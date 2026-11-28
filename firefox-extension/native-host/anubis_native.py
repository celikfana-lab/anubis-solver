#!/usr/bin/env python3
"""anubis_native.py — the native messaging host for the Firefox extension.

Firefox starts this process and speaks the native messaging protocol on its
standard streams: a 4-byte unsigned length in *native* byte order, then that many
bytes of UTF-8 JSON. Messages from the host are limited to 1 MB, which is plenty
for a nonce and a 32-byte digest.

The actual solving is done by libanubis_solver.so through the repository's own
Python module — the same C engine the CLI uses, with the SHA-NI/AVX2 kernels and
every core. That is the whole point of the extension: the page can only run one
core of WebAssembly.

Commands
    {"cmd": "ping"}                                   -> {"ok": true, "pong": true}
    {"cmd": "info"}                                   -> version/threads/cpu info
    {"cmd": "solve", "algorithm": ..., "randomData": ..., "difficulty": ...}
                                                     -> nonce, response hex, timing
    {"cmd": "verify", "algorithm": ..., "randomData": ..., "difficulty": ..., "nonce": ...}
                                                     -> whether the nonce is valid

Nothing is ever written to stdout except framed responses; diagnostics go to
stderr, which Firefox forwards to the browser console.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import threading
import time
from pathlib import Path

MAX_MESSAGE = 1 << 20          # Firefox refuses host messages larger than 1 MB

here = Path(__file__).resolve().parent
HERE = here


def _log(*parts: object) -> None:
    print("[anubis-native]", *parts, file=sys.stderr, flush=True)


def _solver_roots() -> list[Path]:
    """Where the Python module and the shared library may live.

    Two layouts have to work, because the same file is used for both:

      checkout   firefox-extension/native-host/anubis_native.py
                 with anubis_solver.py and libanubis_solver.so two levels up
      dist       <somewhere>/anubis-solver-<ver>-<os>/
                 with the module and the library right here, next to the host

    ANUBIS_SOLVER_HOME overrides both, and ANUBIS_SOLVER_LIB names a library
    file directly.
    """
    roots: list[Path] = []
    env = os.environ.get("ANUBIS_SOLVER_HOME")
    if env:
        roots.append(Path(env))
    roots.extend([HERE, HERE.parent, HERE.parent.parent])
    seen, out = set(), []
    for root in roots:
        try:
            key = root.resolve()
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            out.append(root)
    return out


def _load_solver():
    """Import anubis_solver from whichever layout we are running in."""
    roots = _solver_roots()
    for root in roots:
        if (root / "anubis_solver.py").exists():
            sys.path.insert(0, str(root))
            break
    else:
        tried = ", ".join(str(r) for r in roots)
        raise SystemExit(
            "cannot find anubis_solver.py next to the host; looked in: "
            f"{tried}. Set ANUBIS_SOLVER_HOME to the directory that holds it."
        )

    # A library shipped beside the host wins over anything else, so a dist
    # directory is self-contained.
    for name in ("libanubis_solver.so", "libanubis_solver.dylib", "anubis_solver.dll"):
        candidate = HERE / name
        if candidate.exists() and not os.environ.get("ANUBIS_SOLVER_LIB"):
            os.environ["ANUBIS_SOLVER_LIB"] = str(candidate)
            break

    try:
        import anubis_solver  # noqa: PLC0415
    except Exception as err:  # pragma: no cover - only on a broken install
        raise SystemExit(
            f"cannot import anubis_solver ({err}); set ANUBIS_SOLVER_HOME to the "
            "directory that holds anubis_solver.py and libanubis_solver.so"
        ) from err
    return anubis_solver


def read_exact(stream, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return b""
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_message(stream) -> dict | None:
    header = read_exact(stream, 4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("=I", header)
    if length == 0 or length > 64 << 20:
        raise ValueError(f"refusing a {length}-byte message")
    body = read_exact(stream, length)
    if len(body) < length:
        return None
    return json.loads(body.decode("utf-8"))


def write_message(stream, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE:
        raise ValueError(f"reply of {len(body)} bytes exceeds the 1 MB limit")
    stream.write(struct.pack("=I", len(body)))
    stream.write(body)
    stream.flush()


def _engine_hint(solver) -> str:
    """The backend a solve will most likely pick: the best one that answers."""
    try:
        available = solver.backends()
    except Exception:
        return solver.active_kernel()
    for name in ("cuda", "levelzero", "vulkan", "opencl"):
        if name in available:
            return name
    return "cpu"


def _payload_solution(module, solver, payload: dict):
    """The library's own payload shape, so its parser does the work."""
    return solver.solve({
        "rules": {"algorithm": str(payload.get("algorithm", "")).lower(),
                  "difficulty": int(payload.get("difficulty", 0))},
        "challenge": {"id": payload.get("id") or "",
                      "randomData": str(payload.get("randomData", "")),
                      "method": str(payload.get("algorithm", "")).lower()},
    })


# Throughput actually measured, per (algorithm, payload size, kernel). A solve
# stops at its first hit, so its own nonces-hashed/elapsed is a true sample;
# anything derived from a short probe is not (each solve pays its backend's
# start-up, which swamps small work). The first solve for a shape therefore
# reports no percentage instead of inventing one, and what it measures is kept
# in a small cache so the next solve - and the next browser session - has a real
# denominator.
_CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "anubis-solver" / "speeds.json"
_RATES: dict[str, float] | None = None


def _cache_key(algorithm: str, size: int, kernel: str) -> str:
    return f"{algorithm}|{size}|{kernel}"


def _load_rates() -> dict[str, float]:
    global _RATES
    if _RATES is None:
        try:
            _RATES = {k: float(v) for k, v in json.loads(_CACHE.read_text()).items()}
        except Exception:
            _RATES = {}
    return _RATES


def _known_rate(algorithm: str, size: int, kernel: str) -> tuple[float | None, str | None]:
    """A measured rate for this shape: exact kernel first, then any kernel."""
    rates = _load_rates()
    exact = rates.get(_cache_key(algorithm, size, kernel))
    if exact:
        return exact, "measured"
    for key, value in rates.items():
        parts = key.split("|")
        if len(parts) == 3 and parts[0] == algorithm and parts[1] == str(size) and value:
            return value, "previous"
    return None, None


def _remember_rate(algorithm: str, size: int, kernel: str, nonce: int, elapsed: float) -> float:
    if not (elapsed > 0 and nonce >= 0):
        return 0.0
    rate = (nonce + 1) / elapsed
    if not (0 < rate < 1e12):
        return 0.0
    rates = _load_rates()
    rates[_cache_key(algorithm, size, kernel)] = rate
    try:
        _CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CACHE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(rates, indent=1, sort_keys=True))
        tmp.replace(_CACHE)
    except Exception:
        pass
    return rate


def solve_streaming(solver, payload: dict, emit) -> None:
    """Solve while reporting progress: used with `connectNative`, not one-shot.

    The solve runs on a worker thread so the loop can write a frame every ~120 ms;
    a port accepts many messages, which is the whole reason this exists.
    """
    algorithm = str(payload.get("algorithm", "sha256")).lower()
    difficulty = int(payload.get("difficulty", 0))
    random_data = str(payload.get("randomData", ""))
    size = max(0, len(random_data) // 2)
    kernel_hint = _engine_hint(solver)
    rate, rate_source = _known_rate(algorithm, size, kernel_hint)
    estimate_ms = ((2 ** difficulty) / rate * 1000.0) if rate else None
    result: dict = {}
    started = time.perf_counter()

    def work() -> None:
        try:
            solution = _payload_solution(None, solver, payload)
            result.update({
                "ok": True,
                "algorithm": solution.algorithm,
                "nonce": int(solution.nonce),
                "response": solution.response_hex,
                "elapsedMs": (time.perf_counter() - started) * 1000.0,
            })
        except Exception as err:                       # survives a bad challenge
            result.update({"ok": False, "error": f"{type(err).__name__}: {err}"})

    # active_kernel() only knows what the last solve used, so the first frame
    # names the best backend this machine has and the progress frames replace
    # it with what is actually running.
    emit({"event": "start", "algorithm": algorithm, "difficulty": difficulty,
          "kernel": kernel_hint, "rate": rate, "rateSource": rate_source,
          "estimateMs": estimate_ms, "threads": solver.threads,
          "gpu": solver.gpu, "backends": solver.backends()})
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    while thread.is_alive():
        elapsed = (time.perf_counter() - started) * 1000.0
        emit({"event": "progress", "elapsedMs": elapsed,
              "estimateMs": estimate_ms,
              "pct": (min(95.0, elapsed / estimate_ms * 100.0)
                      if estimate_ms else None),
              "rate": rate, "kernel": solver.active_kernel(),
              "gpu": solver.gpu, "threads": solver.threads})
        thread.join(0.12)
    thread.join()
    measured = 0.0
    if result.get("ok"):
        measured = _remember_rate(algorithm, size, solver.active_kernel(),
                                  int(result.get("nonce") or 0),
                                  float(result.get("elapsedMs") or 0) / 1000.0)
    done = {"event": "done", "kernel": solver.active_kernel(),
            "rate": measured or rate, "estimateMs": estimate_ms,
            "gpu": solver.gpu, "measured": bool(measured)}
    done.update(result)
    emit(done)


def main(argv: list[str]) -> int:
    # Firefox passes the manifest path and, since 55, the add-on ID. Neither is
    # needed to solve, but logging them makes install problems diagnosable.
    if len(argv) > 1:
        _log("manifest:", argv[1])
    if len(argv) > 2:
        _log("add-on id:", argv[2])

    module = _load_solver()
    solver = None

    def get_solver():
        nonlocal solver
        if solver is None:
            # ANUBIS_THREADS pins the worker count; useful for benchmarks that need
            # a single-threaded number, and on machines with a busy CPU
            threads = os.environ.get("ANUBIS_THREADS")
            solver = module.AnubisSolver(threads=int(threads) if threads else None)
            _log(
                f"libanubis_solver {solver.version} · {solver.threads} threads · "
                f"sha256 batch {solver.batch_width} · gpu {solver.gpu or 'none'}"
            )
        return solver

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        try:
            request = read_message(stdin)
        except Exception as err:
            _log("bad message:", err)
            return 1
        if request is None:
            return 0                       # the browser closed the pipe

        cmd = str(request.get("cmd", "")).lower()
        try:
            if cmd == "ping":
                reply = {"ok": True, "pong": True}
            elif cmd == "info":
                s = get_solver()
                reply = {
                    "ok": True,
                    "version": s.version,
                    "threads": s.threads,
                    "batchWidth": s.batch_width,
                    "gpu": s.gpu,
                    "kernel": s.active_kernel(),
                    "affinity": s.affinity,
                    "algorithms": sorted(s.ALGORITHMS),
                }
            elif cmd == "solve_stream":
                s = get_solver()
                if not request.get("randomData") or request.get("difficulty") is None:
                    raise ValueError("solve_stream needs randomData and difficulty")
                if str(request.get("algorithm", "")).lower() not in s.ALGORITHMS:
                    raise ValueError(f"unsupported algorithm {request.get('algorithm')!r}")
                solve_streaming(s, request,
                                lambda frame: write_message(stdout, frame))
                continue
            elif cmd == "solve":
                algorithm = str(request.get("algorithm", "")).lower()
                random_data = str(request.get("randomData", ""))
                difficulty = int(request.get("difficulty", 0))
                if algorithm not in get_solver().ALGORITHMS:
                    raise ValueError(f"unsupported algorithm {algorithm!r}")
                # the library's own payload shape, so its parser does the work
                solution = get_solver().solve({
                    "rules": {"algorithm": algorithm, "difficulty": difficulty},
                    "challenge": {"id": "", "randomData": random_data, "method": algorithm},
                })
                reply = {
                    "ok": True,
                    "algorithm": solution.algorithm,
                    "nonce": int(solution.nonce),
                    "response": solution.response_hex,
                    "elapsedMs": float(solution.elapsed_ms),
                }
            elif cmd == "verify":
                algorithm = str(request.get("algorithm", "")).lower()
                random_data = str(request.get("randomData", ""))
                difficulty = int(request.get("difficulty", 0))
                nonce = int(request.get("nonce", 0))
                native = get_solver()._native  # noqa: SLF001 - same package
                if algorithm in ("fast", "slow"):
                    ok, digest = native._verify_nibbles(random_data, nonce, difficulty)
                else:
                    verify = {
                        "sha256": native.verify_bits,
                        "wasm-sha256": native.verify_bits,
                        "argon2id": native.verify_argon2id,
                        "hashx": native.verify_hashx,
                    }[algorithm]
                    ok, digest = verify(random_data, nonce, difficulty)
                reply = {"ok": True, "valid": bool(ok), "response": digest}
            else:
                reply = {"ok": False, "error": f"unknown command {cmd!r}"}
        except Exception as err:                      # never die on one bad request
            reply = {"ok": False, "error": f"{type(err).__name__}: {err}"}

        try:
            write_message(stdout, reply)
        except Exception as err:
            _log("cannot write reply:", err)
            return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
