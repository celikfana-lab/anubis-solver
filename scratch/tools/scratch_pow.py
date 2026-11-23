#!/usr/bin/env python3
"""Solve a live Anubis sha256 challenge with the Scratch project, then submit it.

This is the end-to-end test: fetch the challenge page, hand the raw challenge
bytes to the generated .sb3 (which does the whole nonce search in blocks), take
the nonce it found, and post it to the same `pass-challenge` endpoint a browser
would use.  A 302 with an auth cookie is the server agreeing the proof is good.

    python3 scratch/tools/scratch_pow.py --port 8083

The difficulty has to be small enough to be reachable: this interpreter does
about 40-80 hashes/second, so difficulty 12 (4096 hashes expected) takes a
couple of minutes, and difficulty 21 (2,097,152) takes hours.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

import requests

CHALLENGE_RE = re.compile(
    r'id="anubis_challenge"[^>]*>(.*?)</script>', re.S
)
PASS = "/.within.website/x/cmd/anubis/api/pass-challenge"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8083)
    ap.add_argument("--sb3", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "build", "sha256.sb3"))
    ap.add_argument("--node-path", default=os.environ.get("NODE_PATH", ""))
    ap.add_argument("--timeout", type=float, default=900.0)
    a = ap.parse_args()

    base = "http://%s:%d" % (a.host, a.port)
    s = requests.Session()
    s.headers["User-Agent"] = "scratch-pow/0.1 (pure blocks)"

    t0 = time.time()
    r = s.get(base + "/", timeout=10)
    m = CHALLENGE_RE.search(r.text)
    if not m:
        print("no challenge on the page; status=%d len=%d" % (r.status_code, len(r.text)))
        return 1
    payload = json.loads(m.group(1))
    rules = payload["rules"]
    chal = payload["challenge"]
    algorithm = rules["algorithm"]
    diff = int(rules["difficulty"])
    if algorithm != "sha256":
        print("this project only does sha256, server asked for %r" % algorithm)
        return 1
    raw = bytes.fromhex(chal["randomData"])
    print("challenge: %d raw bytes, difficulty %d, algorithm %s, id %s"
          % (len(raw), diff, algorithm, chal["id"]))

    env = dict(os.environ)
    if a.node_path:
        env["NODE_PATH"] = a.node_path
    cmd = [os.environ.get("NODE_BIN", "node"),
           os.path.join(os.path.dirname(os.path.abspath(__file__)), "solve_challenge.mjs"),
           a.sb3, "--chal", raw.hex(), "--diff", str(diff),
           "--timeout", str(int(a.timeout * 1000))]
    print("solving in blocks:", " ".join(cmd[1:3]), "...")
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    for line in proc.stderr.splitlines():
        if line.strip():
            print(line)
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    if not lines:
        print("solver failed:", proc.stderr[-800:])
        return 1
    res = json.loads(lines[-1])
    print("blocks found nonce %d after %d hashes (%.1f H/s, %.1f s)"
          % (res["nonce"], res["hashes"], res["hps"], res["wall"]))
    print("hash: %s" % res["hash"])
    if not res["found"]:
        return 1

    elapsed = (time.time() - t0) * 1000.0
    params = {
        "response": res["hash"],
        "nonce": str(res["nonce"]),
        "redir": "/",
        "elapsedTime": "%.3f" % elapsed,
        "id": chal["id"],
    }
    pr = s.get(base + PASS, params=params, timeout=15, allow_redirects=False)
    print("pass-challenge: HTTP %d" % pr.status_code)
    print("cookies: %s" % ", ".join(sorted(s.cookies.keys())))
    if pr.status_code not in (200, 302):
        print(pr.text[:600])
        return 1

    # the real test: fetch the protected page again with the cookie
    after = s.get(base + "/", timeout=10)
    challenged = CHALLENGE_RE.search(after.text) is not None
    print("re-fetch: HTTP %d, still challenged: %s, %d bytes"
          % (after.status_code, challenged, len(after.content)))
    if challenged:
        print("server did not accept the proof")
        return 1
    print("PASS: Anubis accepted a proof of work computed entirely in Scratch blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
