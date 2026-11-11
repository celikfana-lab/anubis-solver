#!/usr/bin/env python3
"""
End-to-end test: start a backend, start Anubis in front of it, and let the
C-backed solver pass the challenge and fetch the protected page.

Usage:
    python3 test_local.py                 # build anubis if needed, run fast+slow
    python3 test_local.py --binary /path/to/anubis
    python3 test_local.py -k sha256       # only run the wasm sha256 case (if built)
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisClient, AnubisSolver

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ANUBIS_SRC = Path(
    os.environ.get("ANUBIS_SRC", ROOT.parent / "anubis")
).resolve()

MARKER = "hello from the protected backend"

FAILS = 0


def say(msg: str) -> None:
    print(msg, flush=True)


def check(name: str, cond: bool, detail: str = "") -> bool:
    global FAILS
    if cond:
        say(f"  ok   {name}")
    else:
        FAILS += 1
        say(f"  FAIL {name} {detail}")
    return cond


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        body = f"{MARKER} (path={self.path})".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # silence
        pass


def start_backend() -> tuple[ThreadingHTTPServer, int, threading.Thread]:
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), BackendHandler)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, port, thread


POLICY_TEMPLATE = """\
bots:
  - name: local-solver-test
    user_agent_regex: .
    action: CHALLENGE
    challenge:
      algorithm: {algorithm}
      difficulty: {difficulty}
"""


def start_anubis(
    binary: Path, policy: Path, backend_port: int, log_path: Path
) -> tuple[subprocess.Popen, int, int]:
    port = free_port()
    metrics_port = free_port()
    cmd = [
        str(binary),
        "-bind",
        f"127.0.0.1:{port}",
        "-metrics-bind",
        f"127.0.0.1:{metrics_port}",
        "-target",
        f"http://127.0.0.1:{backend_port}",
        "-policy-fname",
        str(policy),
        "-cookie-secure=false",
        "-cookie-partitioned=false",
        "-cookie-same-site=Lax",
        "-use-remote-address",
        "-slog-level",
        "INFO",
    ]
    log = open(log_path, "wb")
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    return proc, port, metrics_port


def wait_anubis(port: int, proc: subprocess.Popen, log_path: Path, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/"
    last_err: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"anubis exited with {proc.returncode}; log:\n{log_path.read_text(errors='replace')}"
            )
        try:
            requests.get(url, timeout=1.0)
            return
        except Exception as exc:  # connection refused etc.
            last_err = exc
            time.sleep(0.15)
    raise RuntimeError(f"anubis did not start: {last_err}\nlog:\n{log_path.read_text(errors='replace')}")


def build_anubis(src: Path, out: Path) -> Path:
    say(f"building anubis from {src} ...")
    out.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/anubis"],
        cwd=src,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"go build failed:\n{proc.stdout}\n{proc.stderr}")
    say(f"built {out}")
    return out


# ---------------------------------------------------------------------------
# Test case
# ---------------------------------------------------------------------------


def run_case(
    binary: Path,
    algorithm: str,
    difficulty: int,
    threads: int,
    impersonate: str | None = None,
) -> None:
    say(f"\n=== case: algorithm={algorithm} difficulty={difficulty} ===")
    backend, backend_port, _ = start_backend()
    tmpdir = Path(tempfile.mkdtemp(prefix="anubis-e2e-"))
    policy = tmpdir / "policy.yaml"
    policy.write_text(POLICY_TEMPLATE.format(algorithm=algorithm, difficulty=difficulty))
    log_path = tmpdir / "anubis.log"

    proc, port, _ = start_anubis(binary, policy, backend_port, log_path)
    try:
        wait_anubis(port, proc, log_path)
        base = f"http://127.0.0.1:{port}"

        # 1. A plain request must be challenged (we are not yet authorized).
        raw = requests.get(base + "/", timeout=10)
        was_challenged = 'id="anubis_challenge"' in raw.text
        check("unauthenticated request gets a challenge", was_challenged,
              f"status={raw.status_code}")

        # 2. The solver client should get through and reach the backend.
        client = AnubisClient(
            base, threads=threads, timeout=15, impersonate=impersonate
        )
        t0 = time.time()
        resp = client.get("/")
        wall_ms = (time.time() - t0) * 1000

        check("solver reached the backend", MARKER in resp.text,
              f"status={resp.status_code} body={resp.text[:200]!r}")
        check("at least one challenge was solved", len(client.solutions) >= 1,
              f"solutions={client.solutions}")
        if client.solutions:
            sol = client.solutions[0]
            check("solved the configured algorithm",
                  sol.algorithm == algorithm, f"got {sol.algorithm}")
            check("response is 64 hex chars",
                  len(sol.response) == 64 and all(c in "0123456789abcdef" for c in sol.response))
            say(f"       nonce={sol.nonce} solved in {sol.elapsed_ms:.1f} ms "
                f"(end-to-end {wall_ms:.1f} ms)")

        # 3. The auth cookie must now let a fresh request through.
        again = client.session.get(base + "/", timeout=10)
        check("cookie keeps access without solving", MARKER in again.text,
              f"status={again.status_code}")
        cookie_names = []
        for c in client.session.cookies:
            cookie_names.append(str(getattr(c, "name", c)))
        check("auth cookie present",
              any("anubis" in str(n) for n in cookie_names),
              f"cookies={cookie_names}")

        # 4. A second, independent client must also be able to solve.
        client2 = AnubisClient(
            base, threads=threads, timeout=15, impersonate=impersonate
        )
        resp2 = client2.get("/")
        check("second client also passes", MARKER in resp2.text)

        say(f"       anubis log: {log_path}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        backend.shutdown()
        backend.server_close()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--anubis-src", type=Path, default=DEFAULT_ANUBIS_SRC)
    parser.add_argument("--threads", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument(
        "--impersonate",
        default=None,
        help='use curl_cffi with this browser profile, e.g. "chrome"',
    )
    parser.add_argument("-k", "--only", default=None)
    args = parser.parse_args(argv)

    if args.only and args.only not in ("fast", "slow", "sha256", "hashx", "argon2id"):
        raise SystemExit("--only must be one of: fast, slow, sha256, hashx, argon2id")

    # Make sure the native library exists.
    solver = AnubisSolver(threads=args.threads)
    say(f"native solver {solver.version} (threads={solver.threads})")

    binary = args.binary
    if binary is None:
        binary = Path("/tmp/anubis-build/anubis")
        if not binary.exists():
            if not args.anubis_src.exists():
                raise SystemExit(
                    f"anubis source not found at {args.anubis_src}; pass --binary"
                )
            binary = build_anubis(args.anubis_src, binary)
    if not binary.exists():
        raise SystemExit(f"anubis binary not found: {binary}")

    difficulty_for = {"fast": 4, "slow": 4, "sha256": 16, "hashx": 8, "argon2id": 2}
    cases = [(name, difficulty_for[name]) for name in ("fast", "slow", "sha256", "hashx", "argon2id")]
    if args.only:
        cases = [(args.only, difficulty_for[args.only])]

    for algorithm, difficulty in cases:
        run_case(
            binary, algorithm, difficulty, args.threads, args.impersonate
        )

    say("")
    if FAILS:
        say(f"{FAILS} check(s) FAILED")
        return 1
    say("all end-to-end checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
