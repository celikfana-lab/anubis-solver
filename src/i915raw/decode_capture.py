#!/usr/bin/env python3
"""Decode a captured i915 batch with Intel's own field definitions.

Mesa ships the exact bit layouts of every command in src/intel/genxml/*.xml,
and the commands are inherited across generations (gen120 imports gen110
imports gen90 ... gen80), so the file that actually defines GPGPU_WALKER for
this GPU is gen80.xml, and STATE_BASE_ADDRESS is the 22-dword gen110 form.
Reading those beats guessing at dwords.

    python3 src/i915raw/decode_capture.py --dump /tmp/i915dump --sub 8 \\
        --genxml /media/.../mesa/src/intel/genxml

It prints every command in the submission's batch with its fields, then the
interface descriptor and the surface states it points at, when it can find
them in the dump.
"""
from __future__ import annotations

import argparse
import glob
import os
import struct
import sys
import xml.etree.ElementTree as ET

# (name, mask, match, file that defines the fields)
COMMANDS = [
    ("PIPELINE_SELECT", 0xffff0000, 0x69040000, "gen120.xml"),
    ("STATE_BASE_ADDRESS", 0xffff0000, 0x61010000, "gen110.xml"),
    ("MEDIA_VFE_STATE", 0xffff0000, 0x70000000, "gen110.xml"),
    ("MEDIA_INTERFACE_DESCRIPTOR_LOAD", 0xffff0000, 0x70020000, "gen60.xml"),
    ("MEDIA_CURBE_LOAD", 0xffff0000, 0x70010000, "gen110.xml"),
    ("GPGPU_WALKER", 0xffff0000, 0x71050000, "gen80.xml"),
    ("PIPE_CONTROL", 0xffff0000, 0x7a000000, "gen120.xml"),
    ("MI_LOAD_REGISTER_IMM", 0xffffffff, 0x11020001, "gen120.xml"),
    ("MI_BATCH_BUFFER_START", 0xffff0000, 0x18800000, None),
    ("MI_BATCH_BUFFER_END", 0xffffffff, 0x05000000, None),
    ("MI_NOOP", 0xffffffff, 0x00000000, None),
]


def load_fields(xml_dir: str, fname: str) -> dict[str, list[tuple]]:
    """name -> [(dword, lo, hi, field name, type)] for one genxml file."""
    out: dict[str, list[tuple]] = {}
    path = os.path.join(xml_dir, fname)
    if not os.path.exists(path):
        return out
    root = ET.parse(path).getroot()
    for node in root:
        if node.tag not in ("instruction", "struct"):
            continue
        name = node.get("name")
        fields = []
        for f in node.iter("field"):
            bits = f.get("bits")
            if not bits or ":" not in bits:
                continue
            hi, lo = (int(x) for x in bits.split(":"))
            fields.append((int(f.get("dword")), lo, hi, f.get("name"),
                           f.get("type")))
        out[name] = fields
    return out


def extract(words: list[int], dword: int, lo: int, hi: int) -> int:
    start = dword * 32 + lo
    width = hi - lo + 1
    acc = 0
    for i in range(start, start + width):
        bit = (words[i // 32] >> (i % 32)) & 1 if i // 32 < len(words) else 0
        acc |= bit << (i - start)
    return acc


def decode(name: str, words: list[int], fields: list[tuple], indent: int = 0) -> None:
    pad = " " * indent
    print(f"{pad}{name}  ({len(words)} dwords: "
          + " ".join("%08x" % w for w in words[:6]) +
          ("" if len(words) <= 6 else " ...") + ")")
    for dword, lo, hi, fname, ftype in fields:
        v = extract(words, dword, lo, hi)
        if ftype == "address":
            v <<= 12
        elif ftype == "offset" and v:
            pass
        if v == 0 and ftype in ("address", "offset"):
            continue
        shown = "0x%x" % v if ftype in ("address", "offset") or v > 0xff else str(v)
        print(f"{pad}   dw{dword:<2} {fname:<38} {shown}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", default="/tmp/i915dump")
    ap.add_argument("--sub", type=int, default=0,
                    help="submission number (0 = the last one)")
    ap.add_argument("--genxml",
                    default="/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/mesa/src/intel/genxml")
    ap.add_argument("--batch-va", type=lambda s: int(s, 0), default=None,
                    help="decode this object instead of the submission batch")
    args = ap.parse_args()

    subs = []
    with open(os.path.join(args.dump, "log.txt")) as f:
        cur = None
        for line in f:
            if line.startswith("SUB "):
                parts = line.split()
                cur = {"n": int(parts[1]), "objs": [],
                       "batch_len": int(parts[7]),
                       "batch_start": int(parts[9])}
                subs.append(cur)
            elif line.startswith("OBJ ") and cur is not None:
                _, sub, idx, handle, size, va, flags = line.split()[:7]
                cur["objs"].append({"idx": int(idx), "handle": int(handle),
                                    "size": int(size), "va": int(va, 16)})
    if not subs:
        print("no submissions in the manifest", file=sys.stderr)
        return 1
    sub = subs[-1] if args.sub == 0 else next(s for s in subs if s["n"] == args.sub)

    batch = sub["objs"][-1]
    path = os.path.join(args.dump,
                        "sub%03d-obj-idx%d-h%d.bin" % (sub["n"], batch["idx"],
                                                       batch["handle"]))
    data = open(path, "rb").read()
    start = sub["batch_start"]
    print(f"submission {sub['n']}: batch handle {batch['handle']} "
          f"va 0x{batch['va']:x}, {os.path.basename(path)}")

    words = list(struct.unpack("<%dI" % (len(data) // 4), data))
    lo = start // 4
    hi = lo + sub["batch_len"] // 4
    words = words[lo:hi]
    print("batch_start %d, batch_len %d" % (start, sub["batch_len"]))
    table = {}
    i = 0
    while i < len(words):
        w = words[i]
        cmd = next((c for c in COMMANDS if (w & c[1]) == c[2]), None)
        if cmd is None:
            i += 1
            continue
        name, _, _, fname = cmd
        if fname and fname not in table:
            table[fname] = load_fields(args.genxml, fname)
        fields = table.get(fname, {}).get(name, [])
        length = 1
        for dword, lo, hi, f, t in fields:
            if f in ("DWordLength", "DWord Length") and dword == 0 and lo == 0:
                length = extract(words[i:i + 1], 0, lo, hi) + 2
                break
        if name == "MI_BATCH_BUFFER_START":
            length = 3
        if name == "MI_NOOP":
            i += 1
            continue
        decode(name, words[i:i + length], fields)
        i += length
    return 0


if __name__ == "__main__":
    sys.exit(main())
