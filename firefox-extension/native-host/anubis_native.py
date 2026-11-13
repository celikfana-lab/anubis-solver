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
            solver = module.AnubisSolver()
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
                    "affinity": s.affinity,
                    "algorithms": sorted(s.ALGORITHMS),
                }
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
