#!/usr/bin/env python3
"""Test the generated Scratch SHA-256 project against hashlib.

Runs the real scratch-vm (the interpreter TurboWarp and scratch.mit.edu use) on
scratch/build/sha256.sb3 for a set of messages, and compares the digest the
project reports with CPython's hashlib.  Prints a table with the interpreter
time per hash.

    python3 scratch/tools/verify_sha256.py [--repeats N]

`--repeats` presses the green flag more than once on a single loaded VM, which
also proves the project is re-entrant (it must not pad its input in place).
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SB3 = os.path.join(HERE, "..", "build", "sha256.sb3")  # overridden by --sb3
NODE = os.environ.get("NODE_BIN", "node")
NODE_PATH = os.environ.get("NODE_PATH", "")


def vectors():
    out = [
        ("empty", []),
        ("a", [ord("a")]),
        ("abc", list(b"abc")),
        ("abcde", list(b"abcde")),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", list(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        ("a*55", [ord("a")] * 55),
        ("a*56", [ord("a")] * 56),   # 0x80 lands exactly on the last byte
        ("a*57", [ord("a")] * 57),   # first extra block
        ("a*63", [ord("a")] * 63),
        ("a*64", [ord("a")] * 64),   # one full block, no padding block
        ("a*65", [ord("a")] * 65),
        ("a*119", [ord("a")] * 119),
        ("a*120", [ord("a")] * 120),
        ("bytes 0..255", list(range(256))),
        ("a*1000", [ord("a")] * 1000),
    ]
    rnd = random.Random(20261123)
    for n in (0, 1, 100, 333, 1000):
        out.append(("random %d" % n, [rnd.randrange(256) for _ in range(n)]))
    return out


def run(node_bin, msg, repeats=1, sb3=None):
    env = dict(os.environ)
    if NODE_PATH:
        env["NODE_PATH"] = NODE_PATH
    proc = subprocess.run(
        [node_bin, os.path.join(HERE, "run_sb3.mjs"), sb3 or SB3, json.dumps(msg),
         "--repeats", str(repeats)],
        capture_output=True, text=True, env=env,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    if not lines:
        raise RuntimeError("no result: %s %s" % (proc.stdout[-800:], proc.stderr[-800:]))
    return json.loads(lines[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--node-path", default=os.environ.get("NODE_PATH", ""))
    ap.add_argument("--node", default=NODE)
    ap.add_argument("--sb3", default=None, help="project to test (default build/sha256.sb3)")
    args = ap.parse_args()
    global NODE_PATH, SB3
    NODE_PATH = args.node_path
    if args.sb3:
        SB3 = args.sb3

    if not os.path.exists(SB3):
        sys.exit("missing %s -- run scratch/gen_sha256.py first" % SB3)

    print("%-16s %8s  %-64s %s" % ("message", "bytes", "digest", "verdict"))
    ok = True
    for name, msg in vectors():
        res = run(args.node, msg, args.repeats, SB3)
        want = hashlib.sha256(bytes(msg)).hexdigest()
        got = res.get("hex", "")
        good = got == want
        ok &= good
        print("%-16s %8d  %-64s %s%s" % (
            name, len(msg), got or "<none>",
            "ok" if good else "MISMATCH, want %s" % want,
            "" if args.repeats == 1 else "  (%d runs, %.1f ms)" % (args.repeats, res.get("ms", 0)),
        ))

    # timing, separately: one fresh VM per measurement
    print()
    print("%-16s %8s %10s %12s" % ("message", "bytes", "ms", "bytes/s"))
    for name, msg in [("empty", []), ("abc", list(b"abc")), ("64 B", [7] * 64),
                      ("1 KiB", [7] * 1024), ("4 KiB", [7] * 4096)]:
        best = min(run(args.node, msg, 1, SB3)["ms"] for _ in range(3))
        rate = len(msg) / (best / 1000.0) if best else 0.0
        print("%-16s %8d %10.1f %12.0f" % (name, len(msg), best, rate))

    print()
    print("all vectors ok" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
