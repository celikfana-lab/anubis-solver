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


def write_only(proc: subprocess.Popen, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    proc.stdin.write(struct.pack("=I", len(body)))
    proc.stdin.write(body)
    proc.stdin.flush()


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
                # the port path the extension uses: a stream of frames, so a
                # progress bar can show what is working and how fast
                frames = []
                write_only(proc, {
                    "cmd": "solve_stream",
                    "algorithm": rules["algorithm"],
                    "randomData": chal["randomData"],
                    "difficulty": rules["difficulty"],
                })
                while True:
                    frame = read_message(proc.stdout)
                    frames.append(frame)
                    if frame.get("event") in ("done", "error"):
                        break
                start, done = frames[0], frames[-1]
                check("stream: the first frame names the engine",
                      start.get("event") == "start" and bool(start.get("kernel")),
                      f"{start.get('kernel')} at {start.get('rate', 0) / 1e6:.2f} MH/s, "
                      f"~{start.get('estimateMs', 0) / 1000:.1f} s")
                check("stream: progress frames are well formed",
                      all(0 <= f.get("pct", 0) <= 99 for f in frames[1:-1]),
                      f"{len(frames) - 2} progress frame(s)")
                check("stream: the last frame carries the proof",
                      done.get("event") == "done" and done.get("ok") is True
                      and done.get("nonce") is not None,
                      f"nonce {done.get('nonce')} in {done.get('elapsedMs', 0):.0f} ms")
                check("stream: same proof as the one-shot path",
                      done.get("response") == solved.get("response"))

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
