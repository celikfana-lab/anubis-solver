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

# The extension is installed beside this checkout; find the library from here.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def _log(*parts: object) -> None:
    print("[anubis-native]", *parts, file=sys.stderr, flush=True)


def _load_solver():
    """Import the repository's Python module, wherever this checkout lives."""
    sys.path.insert(0, str(REPO))
    try:
        import anubis_solver  # noqa: PLC0415
    except Exception as err:  # pragma: no cover - only on a broken checkout
        raise SystemExit(f"cannot import anubis_solver from {REPO}: {err}") from err
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


def _calibrate(solver, algorithm: str, difficulty: int) -> float:
    """Hashes per second for this algorithm here, measured a few bits lower.

    A bar needs a denominator. Asking for a difficulty 8 bits under the real one
    is 1/256 of the work on the same program, threads and cache, and the elapsed
    time the library reports turns that into a rate.
    """
    d = max(10, min(difficulty - 4, 20))
    best = 0.0
    for _ in range(3):
        probe = {"algorithm": algorithm, "difficulty": d,
                 "randomData": os.urandom(32).hex()}
        started = time.perf_counter()
        _payload_solution(None, solver, probe)
        elapsed = max(time.perf_counter() - started, 1e-6)
        if elapsed > 0.6 and d > 10:
            d -= 4                       # too slow to be a probe: shrink, retry
            continue
        # the first probe pays the library's warm-up; a maximum over the probes
        # is closer to the steady-state rate the real solve will see
        best = max(best, (2 ** d) / elapsed)
    return best or 1e6


def solve_streaming(solver, payload: dict, emit) -> None:
    """Solve while reporting progress: used with `connectNative`, not one-shot.

    The solve runs on a worker thread so the loop can write a frame every ~120 ms;
    a port accepts many messages, which is the whole reason this exists.
    """
    algorithm = str(payload.get("algorithm", "sha256")).lower()
    difficulty = int(payload.get("difficulty", 0))
    rate = _calibrate(solver, algorithm, difficulty)
    estimate_ms = (2 ** difficulty) / max(rate, 1.0) * 1000.0
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
          "kernel": _engine_hint(solver), "rate": rate,
          "estimateMs": estimate_ms, "threads": solver.threads,
          "gpu": solver.gpu, "backends": solver.backends()})
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    while thread.is_alive():
        elapsed = (time.perf_counter() - started) * 1000.0
        emit({"event": "progress", "elapsedMs": elapsed,
              "estimateMs": estimate_ms,
              "pct": min(99.0, elapsed / max(estimate_ms, 1.0) * 100.0),
              "rate": rate, "kernel": solver.active_kernel(),
              "gpu": solver.gpu, "threads": solver.threads})
        thread.join(0.12)
    thread.join()
    done = {"event": "done", "kernel": solver.active_kernel(), "rate": rate,
            "estimateMs": estimate_ms, "gpu": solver.gpu}
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
