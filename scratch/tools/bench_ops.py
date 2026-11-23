#!/usr/bin/env python3
"""Micro-benchmark the per-operation cost of the real Scratch interpreter.

The SHA-256 port is ~90 % bitwise work by statement count, so it is worth
knowing what one statement actually costs -- and especially what a *custom
block call* costs, because scratch-vm re-parses the procedure signature on
every call.

Generates one tiny project per row, runs each in scratch-vm N times through the
loop, and reports microseconds per operation.

    python3 scratch/tools/bench_ops.py [--n 20000]
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sb3 import BLANK_SVG, Project  # noqa: E402

BUILD = os.path.join(HERE, "..", "build", "bench")
NODE = os.environ.get("NODE_BIN", "node")
NODE_PATH = os.environ.get("NODE_PATH", "")


def bitwise_proc(st, proc, table, stride, steps):
    d, _ = st.def_proc(proc, ["a", "b"])
    loop = [
        st.setv("IDX", st.add(st.mul(st.mod(st.getv("Z"), stride), stride),
                              st.mod(st.getv("Q"), stride))),
        st.changev("ACC", st.mul(st.item(table, st.add(st.getv("IDX"), 1)),
                                 st.getv("SCALE"))),
        st.setv("Z", st.floor(st.div(st.getv("Z"), stride))),
        st.setv("Q", st.floor(st.div(st.getv("Q"), stride))),
        st.setv("SCALE", st.mul(st.getv("SCALE"), stride)),
    ]
    st.chain(d,
             st.setv("ACC", 0),
             st.setv("SCALE", 1),
             st.setv("Z", st.arg("a")),
             st.setv("Q", st.arg("b")),
             st.repeat(steps, st.chain(*loop)),
             st.setv("IRES", st.getv("ACC")))
    st.script(d)


def build(name, body_fn, tables=None, n=20000):
    p = Project()
    st = p.stage()
    p.costume(st, "blank", BLANK_SVG, 1, 1)
    for v in ("T0", "T1", "ACC", "SCALE", "Z", "Q", "IDX", "IRES", "DONE"):
        st.var(v, 0)
    st.lst("K", [0x428A2F98, 0x71374491])
    if tables == 4:
        stride, steps = 16, 8
    else:
        stride, steps = 256, 4
    if tables:
        n_entries = stride * stride
        st.lst("XOR_T", [float((i // stride) ^ (i % stride)) for i in range(n_entries)])
        bitwise_proc(st, "xor32 %s %s", "XOR_T", stride, steps)
    d, _ = st.def_proc("add32 %s %s", ["a", "b"])
    st.chain(d, st.setv("IRES", st.mod(st.add(st.arg("a"), st.arg("b")), 4294967296)))
    st.script(d)

    flag = st.when_flag()
    inner = body_fn(st)
    st.chain(flag, st.setv("DONE", 0), st.repeat(n, st.chain(*inner)), st.setv("DONE", 1))
    st.script(flag)
    path = os.path.join(BUILD, name + ".sb3")
    p.save(path)
    return path, n


def run(path):
    env = dict(os.environ)
    if NODE_PATH:
        env["NODE_PATH"] = NODE_PATH
    proc = subprocess.run(
        [NODE, os.path.join(HERE, "run_sb3.mjs"), path, "[]", "--repeats", "3"],
        capture_output=True, text=True, env=env,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    if not lines:
        raise RuntimeError(proc.stdout[-500:] + proc.stderr[-500:])
    return json.loads(lines[-1])["ms"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--node-path", default=os.environ.get("NODE_PATH", ""))
    a = ap.parse_args()
    global NODE_PATH
    NODE_PATH = a.node_path
    os.makedirs(BUILD, exist_ok=True)
    n = a.n
    runs = 3

    cases = []

    def empty(st):
        return [st.changev("T0", 1)]

    def one_add_call(st):
        return [st.call_proc("add32 %s %s", [0x12345678, 0x0F0F0F0F])]

    def xor_call(tables):
        def f(st):
            return [st.call_proc("xor32 %s %s", [0x12345678, 0x0F0F0F0F])]
        return f

    def inline_xor(stride, steps):
        def f(st):
            out = [st.setv("ACC", 0), st.setv("SCALE", 1),
                   st.setv("Z", 0x12345678), st.setv("Q", 0x0F0F0F0F)]
            loop = [
                st.setv("IDX", st.add(st.mul(st.mod(st.getv("Z"), stride), stride),
                                      st.mod(st.getv("Q"), stride))),
                st.changev("ACC", st.mul(st.item("XOR_T", st.add(st.getv("IDX"), 1)),
                                         st.getv("SCALE"))),
                st.setv("Z", st.floor(st.div(st.getv("Z"), stride))),
                st.setv("Q", st.floor(st.div(st.getv("Q"), stride))),
                st.setv("SCALE", st.mul(st.getv("SCALE"), stride)),
            ]
            out.append(st.repeat(steps, st.chain(*loop)))
            return out
        return f

    def listread(st):
        return [st.setv("T1", st.item("K", 1))]

    def setvar(st):
        return [st.setv("T1", 7)]

    cases = [
        ("nop            (change T0 by 1)", empty, None),
        ("add32 call                ", one_add_call, None),
        ("xor32 call, 16x16 tables  ", xor_call(4), 4),
        ("xor32 call, 256x256 tables", xor_call(8), 8),
        ("xor32 inlined, 16x16      ", inline_xor(16, 8), 4),
        ("xor32 inlined, 256x256    ", inline_xor(256, 4), 8),
        ("list item read            ", listread, None),
        ("set variable              ", setvar, None),
    ]

    print("%-28s %10s %12s" % ("operation", "us/op", "ops/s"))
    baseline = None
    for label, fn, tables in cases:
        path, count = build(label.strip().replace(" ", "_").replace("(", "").replace(")", "")
                            .replace(",", "").replace("x", "")[:30], fn, tables, n)
        best = min(run(path) for _ in range(runs))
        per_call = best / runs / count * 1000.0  # us (ms is summed over repeats)
        if baseline is None:
            baseline = per_call
        print("%-28s %10.3f %12.0f" % (label, per_call, 1e6 / per_call))
    print()
    print("note: us/op is interpreter time only (scratch-vm _step), %d loop iterations" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
