#!/usr/bin/env python3
"""test-native.py — exercise the native host exactly as Firefox would.

Spawns the host, speaks the 4-byte-length + JSON protocol on its pipes, and checks
that a challenge from a *live* Anubis is solved and accepted. No browser needed.

    python3 firefox-extension/test-native.py [--url http://127.0.0.1:8923/]
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode

import urllib.request

HERE = Path(__file__).resolve().parent
HOST = HERE / "native-host" / "anubis_native.py"
REPO = HERE.parent


def read_message(stream) -> dict:
    header = stream.read(4)
    if len(header) < 4:
        raise SystemExit("host closed the pipe")
    (length,) = struct.unpack("=I", header)
    return json.loads(stream.read(length).decode())


def send(proc: subprocess.Popen, payload: dict) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode()
    proc.stdin.write(struct.pack("=I", len(body)))
    proc.stdin.write(body)
    proc.stdin.flush()
    return read_message(proc.stdout)


def parse_challenge(html: str) -> dict | None:
    import re
    m = re.search(r'id="anubis_challenge"[^>]*>\s*(\{.*?\})\s*</script>', html, re.S)
    return json.loads(m.group(1)) if m else None


def main() -> int:
    base = "http://127.0.0.1:8923/"
    for i, arg in enumerate(sys.argv):
        if arg == "--url" and i + 1 < len(sys.argv):
            base = sys.argv[i + 1]

    proc = subprocess.Popen(
        [sys.executable, "-u", str(HOST), "manifest.json", "anubis-solver@celikfana-lab"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=False,
    )
    failures = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'ok  ' if ok else 'FAIL'} {label}{'  ' + detail if detail else ''}")
        if not ok:
            failures += 1

    try:
        pong = send(proc, {"cmd": "ping"})
        check("ping", pong.get("ok") is True and pong.get("pong") is True)

        info = send(proc, {"cmd": "info"})
        check("info", info.get("ok") is True,
              f"libanubis_solver {info.get('version')}, {info.get('threads')} threads, "
              f"sha256 batch {info.get('batchWidth')}, gpu {info.get('gpu')}")

        bad = send(proc, {"cmd": "nonsense"})
        check("unknown command is an error, not a crash", bad.get("ok") is False, bad.get("error", ""))

        # a live challenge, if a server is up. One opener for the whole exchange:
        # Anubis sets a cookie on the first page load and the pass-challenge call
        # must carry it, which is what the browser would do.
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        try:
            html = opener.open(base, timeout=5).read().decode()
            challenge = parse_challenge(html)
        except Exception as err:
            challenge = None
            print(f"  skip live solve: {err}")

        if challenge:
            rules, chal = challenge["rules"], challenge["challenge"]
            solved = send(proc, {
                "cmd": "solve",
                "algorithm": rules["algorithm"],
                "randomData": chal["randomData"],
                "difficulty": rules["difficulty"],
            })
            check(f"live solve ({rules['algorithm']} difficulty {rules['difficulty']})",
                  solved.get("ok") is True,
                  f"nonce {solved.get('nonce')} in {solved.get('elapsedMs', 0):.2f} ms")

            verified = send(proc, {
                "cmd": "verify",
                "algorithm": rules["algorithm"],
                "randomData": chal["randomData"],
                "difficulty": rules["difficulty"],
                "nonce": solved.get("nonce"),
            })
            check("the engine agrees the nonce is valid", verified.get("valid") is True)

            if solved.get("ok"):
                # the real proof: hand the response to the server and fetch the page
                query = urlencode({
                    "id": chal["id"],
                    "response": solved["response"],
                    "nonce": solved["nonce"],
                    "redir": "/",
                    "elapsedTime": max(1, round(solved.get("elapsedMs", 1))),
                })
                pass_url = base.rstrip("/") + "/.within.website/x/cmd/anubis/api/pass-challenge?" + query
                opener.open(pass_url, timeout=10).read()
                page = opener.open(base, timeout=10).read().decode()
                check("the server let the native solve through", "PAST THE WALL" in page,
                      f"{len(page)} bytes after the wall")
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)

    print()
    print("all checks passed" if failures == 0 else f"{failures} check(s) FAILED")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
