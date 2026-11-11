#!/usr/bin/env python3
"""
Compatibility matrix: run the C/Python solver against every stable Anubis
release, built from this checkout's git tags.

For each tag it:
  * creates a git worktree,
  * supplies the generated assets the tag's `go:embed` needs (stubs for
    browser-only JS, real WASM modules for v1.28+),
  * builds `cmd/anubis`,
  * starts it in front of a backend,
  * asks the solver to pass each challenge algorithm that release supports,
  * records PASS / FAIL / BUILD_FAIL / START_FAIL.

Usage:
    python3 test_versions.py              # all stable tags
    python3 test_versions.py -t v1.14.2 -t v1.28.2
    python3 test_versions.py --fast-only  # just "fast" on every tag
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisClient

ROOT = Path(__file__).resolve().parent.parent
ANUBIS_SRC = Path(os.environ.get("ANUBIS_SRC", ROOT.parent / "anubis")).resolve()
WORK = Path(os.environ.get("ANUBIS_VERSION_WORK", "/tmp/anubis-versions"))
MARKER = "backend-ok"

DIFFICULTY = {"fast": 4, "slow": 4, "sha256": 12, "hashx": 8, "argon2id": 2}


def say(msg: str) -> None:
    print(msg, flush=True)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        body = f"{MARKER}: {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------


def git(*args: str, cwd: Path = ANUBIS_SRC) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout


def stable_tags(include_prereleases: bool = False) -> list[str]:
    tags = git("tag", "--sort=v:refname").split()
    out = []
    for tag in tags:
        if tag.endswith(".signed"):
            continue
        if include_prereleases or re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            if version_tuple(tag) is not None:
                out.append(tag)
    return out


def version_tuple(tag: str) -> tuple[int, int, int] | None:
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# per-tag preparation
# ---------------------------------------------------------------------------


def prepare_worktree(tag: str) -> Path:
    path = WORK / tag
    if (path / ".git").exists():
        return path
    if path.exists():
        shutil.rmtree(path)
    WORK.mkdir(parents=True, exist_ok=True)
    git("worktree", "add", "--force", str(path), tag)
    return path


def write_if_missing(path: Path, content: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def prep_assets(path: Path) -> None:
    # Browser-only embeds: stubs are fine because the solver never runs JS.
    write_if_missing(path / "lib/challenge/preact/static/app.js", "/* stub */\n")
    write_if_missing(
        path / "lib/challenge/challengepage/static/js/bootstrap.mjs",
        "/* stub */\n",
    )
    write_if_missing(
        path / "lib/challenge/proofofwork/static/js/bootstrap.mjs",
        "/* stub */\n",
    )

    # WASM challenge modules are loaded and executed by the server, so these
    # must be the real artifacts. The Rust sources are identical across
    # v1.28.0..v1.28.2, so one build serves all of them.
    if (path / "wasm/scripts/build_wasm.sh").exists():
        built = ANUBIS_SRC / "web/static/wasm"
        for kind in ("simd128", "baseline"):
            target = path / "web/static/wasm" / kind
            target.mkdir(parents=True, exist_ok=True)
            for wasm in (built / kind).glob("*.wasm"):
                shutil.copy2(wasm, target / wasm.name)


def available_flags(path: Path) -> set[str]:
    main = path / "cmd/anubis/main.go"
    if not main.exists():
        return set()
    text = main.read_text(errors="replace")
    return set(
        re.findall(
            r'flag\.(?:String|Int|Bool|Duration)\("([a-zA-Z0-9-]+)"', text
        )
    )


def build_tag(path: Path) -> tuple[Path | None, str]:
    binary = path / "anubis"
    proc = subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/anubis"],
        cwd=path,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout)[-2000:]
    return binary, ""


# ---------------------------------------------------------------------------
# policy files
# ---------------------------------------------------------------------------

JSON_POLICY = json.dumps(
    {
        "bots": [{"name": "all", "user_agent_regex": ".", "action": "CHALLENGE"}],
        "dnsbl": False,
    }
)


def policy_text(path: Path, algorithm: str | None, difficulty: int) -> str:
    if (path / "data/botPolicies.yaml").exists():
        text = "bots:\n  - name: all\n    user_agent_regex: .\n    action: CHALLENGE\n"
        if algorithm:
            text += (
                "    challenge:\n"
                f"      algorithm: {algorithm}\n"
                f"      difficulty: {difficulty}\n"
            )
        return text
    return JSON_POLICY


# ---------------------------------------------------------------------------
# running one case
# ---------------------------------------------------------------------------


def run_case(
    tag: str,
    binary: Path,
    flags: set[str],
    algorithm: str,
    workdir: Path,
    backend_port: int,
    threads: int,
) -> dict:
    difficulty = DIFFICULTY.get(algorithm, 4)
    policy = workdir / f"policy-{algorithm}.yaml"
    policy.write_text(policy_text(workdir, algorithm, difficulty))
    log_path = workdir / f"anubis-{algorithm}.log"

    port = free_port()
    metrics = free_port()
    cmd = [str(binary)]
    cmd += ["-bind", f"127.0.0.1:{port}"]
    if "metrics-bind" in flags:
        cmd += ["-metrics-bind", f"127.0.0.1:{metrics}"]
    if "target" in flags:
        cmd += ["-target", f"http://127.0.0.1:{backend_port}"]
    if "policy-fname" in flags:
        cmd += ["-policy-fname", str(policy)]
    if "slog-level" in flags:
        cmd += ["-slog-level", "INFO"]
    if "difficulty" in flags:
        cmd += ["-difficulty", str(difficulty)]
    if "use-remote-address" in flags:
        cmd += ["-use-remote-address"]
    if "cookie-secure" in flags:
        cmd += ["-cookie-secure=false"]
    if "cookie-partitioned" in flags:
        cmd += ["-cookie-partitioned=false"]
    if "cookie-same-site" in flags:
        cmd += ["-cookie-same-site=Lax"]

    log = open(log_path, "wb")
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    started = time.time()
    base = f"http://127.0.0.1:{port}"
    headers = {"X-Real-IP": "127.0.0.1"}

    try:
        # Wait for the server.
        ready = False
        for _ in range(250):
            if proc.poll() is not None:
                break
            try:
                requests.get(base + "/", headers=headers, timeout=1)
                ready = True
                break
            except requests.RequestException:
                time.sleep(0.1)
        if not ready:
            return {
                "tag": tag,
                "algorithm": algorithm,
                "status": "START_FAIL",
                "detail": (log_path.read_text(errors="replace") or "")[-800:],
            }

        client = AnubisClient(base, threads=threads, timeout=25)
        resp = client.get("/")
        wall = (time.time() - started) * 1000

        if MARKER not in resp.text:
            return {
                "tag": tag,
                "algorithm": algorithm,
                "status": "FAIL",
                "detail": f"status={resp.status_code} body={resp.text[:200]!r}",
            }

        solved = client.solutions[0] if client.solutions else None
        return {
            "tag": tag,
            "algorithm": algorithm,
            "status": "PASS",
            "solved_algorithm": solved.algorithm if solved else None,
            "nonce": solved.nonce if solved else None,
            "solve_ms": round(solved.elapsed_ms, 1) if solved else None,
            "wall_ms": round(wall, 1),
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def algorithms_for(tag: str, fast_only: bool) -> list[str]:
    if fast_only:
        return ["fast"]
    v = version_tuple(tag) or (0, 0, 0)
    if v >= (1, 28, 0):
        return ["fast", "slow", "sha256", "hashx", "argon2id"]
    if v >= (1, 20, 0):
        return ["fast", "slow"]
    return ["fast"]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--tag", action="append", default=None)
    parser.add_argument("--fast-only", action="store_true")
    parser.add_argument("--include-prereleases", action="store_true")
    parser.add_argument("--threads", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument(
        "--results",
        default=None,
        help="where to write results (default: results/version-matrix[-prereleases].json)",
    )
    args = parser.parse_args(argv)

    tags = args.tag or stable_tags(args.include_prereleases)
    if args.results is None:
        name = (
            "version-matrix-prereleases.json"
            if args.include_prereleases
            else "version-matrix.json"
        )
        args.results = str(ROOT / "results" / name)
    WORK.mkdir(parents=True, exist_ok=True)

    backend = ThreadingHTTPServer(("127.0.0.1", free_port()), BackendHandler)
    backend.daemon_threads = True
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    backend_port = backend.server_address[1]

    results: list[dict] = []
    try:
        for tag in tags:
            say(f"\n=== {tag} ===")
            try:
                path = prepare_worktree(tag)
            except subprocess.CalledProcessError as exc:
                results.append(
                    {"tag": tag, "algorithm": "-", "status": "WORKTREE_FAIL",
                     "detail": (exc.stderr or "")[-500:]}
                )
                say(f"  worktree failed: {exc.stderr[-300:]}")
                continue

            prep_assets(path)
            binary, err = build_tag(path)
            flags = available_flags(path)
            if binary is None:
                results.append(
                    {"tag": tag, "algorithm": "-", "status": "BUILD_FAIL",
                     "detail": err[-1200:]}
                )
                say(f"  BUILD_FAIL: {err.strip().splitlines()[-1] if err.strip() else '?'}")
                continue

            say(f"  built (flags: {sorted(flags)})")
            for algorithm in algorithms_for(tag, args.fast_only):
                # First attempt with the requested algorithm; if the server
                # rejects the policy (older schema), retry with the default.
                res = run_case(
                    tag, binary, flags, algorithm, path, backend_port, args.threads
                )
                if res["status"] == "START_FAIL" and res.get("detail"):
                    res = run_case(
                        tag, binary, flags, None, path, backend_port, args.threads
                    )
                    res["algorithm"] = f"{algorithm} (default policy)"
                if res["status"] == "START_FAIL" and res.get("detail"):
                    # Nothing to solve: the server never came up.
                    res["status"] = "START_FAIL"
                results.append(res)
                status = res["status"]
                extra = ""
                if status == "PASS":
                    extra = (
                        f" solved={res.get('solved_algorithm')} "
                        f"nonce={res.get('nonce')} "
                        f"{res.get('solve_ms')}ms"
                    )
                say(f"  {algorithm:<9} {status}{extra}")
                Path(args.results).write_text(json.dumps(results, indent=2))
    finally:
        backend.shutdown()
        backend.server_close()

    # summary
    say("\n=== summary ===")
    ok = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    say(f"{ok}/{total} cases passed")
    for r in results:
        if r["status"] != "PASS":
            say(f"  {r['tag']:<9} {r.get('algorithm'):<9} {r['status']}")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
