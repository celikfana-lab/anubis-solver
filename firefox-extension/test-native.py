#!/usr/bin/env python3
"""test-native.py — exercise the native host exactly as Firefox would.

Spawns the host, speaks the 4-byte-length + JSON protocol on its pipes, and checks
that a challenge from a *live* Anubis is solved and accepted. No browser needed.

    python3 firefox-extension/test-native.py                          # :8923
    python3 firefox-extension/test-native.py --url http://host:port/
    python3 firefox-extension/test-native.py --start-gate             # sha256, 20
    python3 firefox-extension/test-native.py --start-gate --algorithm hashx --difficulty 26
    python3 firefox-extension/test-native.py --start-anubis           # the real Anubis
    python3 firefox-extension/test-native.py --host /path/anubis_native.py

--start-gate builds a challenge in front of a throwaway backend, so the whole
Anubis exchange (page, challenge JSON, pass-challenge, cookie) runs against
betterAnusbis on a free port, with whichever algorithm and difficulty you ask
for. The default is the sha256 tier: same randomData size Anubis issues, and the
tier the WebGPU and wasm 4-wide kernels implement.

--start-anubis does the same with the real Anubis (Go), built from
$ANUBIS_SRC (default ../anubis) or a binary passed with --anubis-binary. It
starts it the way an http-only local server has to be started, because
Anubis's defaults make the browser drop its own challenge cookie:

    -cookie-secure=false -cookie-partitioned=false -cookie-same-site=Lax
    -use-remote-address

With the defaults (Secure; SameSite=None; Partitioned) a browser on plain
http:// never stores the verification cookie, and /pass-challenge answers
"Your browser is configured to disable cookies" -- the Sad Anubis page. That
is Anubis's own check (lib/anubis.go, PassChallenge), not the extension.
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


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(url: str, timeout: float = 8.0) -> bool:
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5).read()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def start_backend():
    """A throwaway backend whose page the gate's marker is checked against."""
    import tempfile

    www = Path(tempfile.mkdtemp(prefix="anubis-backend-"))
    (www / "index.html").write_text("PAST THE WALL\n")
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        cwd=www, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc, port


def start_gate(algorithm: str, difficulty: int):
    """betterAnusbis in front of a throwaway backend, on free ports."""
    gate_bin = REPO / "betterAnusbis" / "betterAnusbis"
    if not gate_bin.exists():
        raise SystemExit(f"{gate_bin} is not built; run `make -C betterAnusbis` first")

    backend, backend_port = start_backend()
    gate_port = free_port()
    gate = subprocess.Popen(
        [str(gate_bin), "--listen", f"127.0.0.1:{gate_port}",
         "--target", f"http://127.0.0.1:{backend_port}",
         "--algorithm", algorithm, "--difficulty", str(difficulty)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    url = f"http://127.0.0.1:{gate_port}/"
    if not wait_for(url):
        gate.terminate()
        backend.terminate()
        raise SystemExit(f"the gate on {url} never answered")
    print(f"  gate: betterAnusbis, {algorithm} difficulty {difficulty} on {url}")
    return gate, backend, url


ANUBIS_COOKIE_FLAGS = [
    # Anubis defaults to Secure; SameSite=None; Partitioned, which a browser
    # refuses to store on a plain http:// origin. Then /pass-challenge has no
    # verification cookie and answers with the cookies-disabled page.
    "-cookie-secure=false",
    "-cookie-partitioned=false",
    "-cookie-same-site=Lax",
    # no proxy in front of it here, so take the peer address instead of X-Real-IP
    "-use-remote-address",
]


def build_anubis(src: Path) -> Path:
    out = REPO / "build" / "anubis-e2e"
    out.parent.mkdir(exist_ok=True)
    print(f"  building anubis from {src} ...")
    proc = subprocess.run(["go", "build", "-o", str(out), "./cmd/anubis"], cwd=src,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"go build failed:\n{proc.stderr[-2000:]}")
    return out


def start_anubis(algorithm: str, difficulty: int, binary: Path | None):
    """The real Anubis in front of a throwaway backend, http-only friendly."""
    import tempfile

    if binary is None:
        src = Path(__import__("os").environ.get("ANUBIS_SRC", REPO.parent / "anubis"))
        binary = REPO / "build" / "anubis-e2e"
        if not binary.exists() or binary.stat().st_mtime < max(
            p.stat().st_mtime for p in (src / "lib").glob("*.go")
        ):
            binary = build_anubis(src)
    if not Path(binary).exists():
        raise SystemExit(f"{binary} is not there")

    tmp = Path(tempfile.mkdtemp(prefix="anubis-real-"))
    policy = tmp / "botPolicies.yaml"
    policy.write_text(
        "bots:\n"
        "  - name: local-solver-test\n"
        "    user_agent_regex: .\n"
        "    action: CHALLENGE\n"
        "    challenge:\n"
        f"      algorithm: {algorithm}\n"
        f"      difficulty: {difficulty}\n"
    )
    backend, backend_port = start_backend()
    port, metrics = free_port(), free_port()
    proc = subprocess.Popen(
        [str(binary), "-bind", f"127.0.0.1:{port}", "-metrics-bind", f"127.0.0.1:{metrics}",
         "-target", f"http://127.0.0.1:{backend_port}", "-policy-fname", str(policy),
         *ANUBIS_COOKIE_FLAGS, "-slog-level", "WARN"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    url = f"http://127.0.0.1:{port}/"
    if not wait_for(url):
        proc.terminate()
        backend.terminate()
        raise SystemExit(f"anubis on {url} never answered")
    print(f"  gate: real Anubis, {algorithm} difficulty {difficulty} on {url}")
    return proc, backend, url


def main() -> int:
    base = "http://127.0.0.1:8923/"
    host = HOST
    algorithm = "sha256"
    difficulty = 20
    start = False
    real = False
    anubis_binary = None
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--url" and i + 1 < len(args):
            base = args[i + 1]
        elif arg == "--host" and i + 1 < len(args):
            host = Path(args[i + 1])
        elif arg == "--algorithm" and i + 1 < len(args):
            algorithm = args[i + 1]
        elif arg == "--difficulty" and i + 1 < len(args):
            difficulty = int(args[i + 1])
        elif arg == "--start-gate":
            start = True
        elif arg == "--start-anubis":
            real = True
        elif arg == "--anubis-binary" and i + 1 < len(args):
            anubis_binary = Path(args[i + 1])

    gate = backend = None
    if start:
        gate, backend, base = start_gate(algorithm, difficulty)
    elif real:
        gate, backend, base = start_anubis(algorithm, difficulty, anubis_binary)

    if not host.exists():
        raise SystemExit(f"no native host at {host}")
    proc = subprocess.Popen(
        [sys.executable, "-u", str(host), "manifest.json", "anubis-solver@celikfana-lab"],
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
                      start.get("event") == "start" and bool(start.get("kernel"))
                      and bool(start.get("gpu")),
                      f"{start.get('kernel')} on {start.get('gpu')}, "
                      + (f"~{(start.get('rate') or 0) / 1e6:.2f} MH/s, "
                         f"~{(start.get('estimateMs') or 0) / 1000:.1f} s"
                         if start.get("rate") else "no measured rate yet"))
                # pct is null until the host has measured this challenge shape:
                # the first solve of a shape reports no percentage rather than a
                # made-up one, and the bar runs indeterminate instead.
                pcts = [f.get("pct") for f in frames[1:-1]]
                check("stream: progress frames are well formed",
                      all(p is None or 0 <= p <= 95 for p in pcts),
                      f"{len(pcts)} progress frame(s), "
                      f"{sum(p is None for p in pcts)} without a percentage")
                check("stream: the last frame carries the proof",
                      done.get("event") == "done" and done.get("ok") is True
                      and done.get("nonce") is not None,
                      f"nonce {done.get('nonce')} in {done.get('elapsedMs', 0):.0f} ms")
                # A second solve of the same challenge may legitimately find a
                # different nonce (hashx is not deterministic), so the two
                # responses are not expected to be equal: check that the
                # streamed proof is a valid one instead.
                stream_verified = send(proc, {
                    "cmd": "verify",
                    "algorithm": rules["algorithm"],
                    "randomData": chal["randomData"],
                    "difficulty": rules["difficulty"],
                    "nonce": done.get("nonce"),
                })
                check("stream: the proof it streamed is valid",
                      stream_verified.get("valid") is True,
                      f"nonce {done.get('nonce')}")

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
        for child in (gate, backend):
            if child is not None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()

    print()
    print("all checks passed" if failures == 0 else f"{failures} check(s) FAILED")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
