#!/usr/bin/env python3
"""extract.py — build the (SASS text, instruction bytes) oracle.

ptxas compiles PTX to a cubin, the cubin's `.text.<kernel>` section holds the
instructions as 16-byte words, and nvdisasm decodes those same bytes back to
text. Pairing the two gives ground truth for an assembler: for any instruction
text we can see the exact bytes that a working compiler chose.

    python3 sassasm/extract.py kernel.ptx            # print pairs
    python3 sassasm/extract.py --json kernel.ptx     # machine readable

Toolkit lookup order: $SASS_TOOLKIT/bin, /media/.../nvida/bin, /tmp/cudaroot/usr/bin.
Needs ptxas and nvdisasm only; no CUDA headers or driver.
"""
from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

CANDIDATES = [
    os.environ.get("SASS_TOOLKIT", "") + "/bin",
    "/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/nvida/bin",
    "/tmp/cudaroot/usr/bin",
]


def find_tool(name: str) -> str:
    for d in CANDIDATES:
        p = Path(d) / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    raise SystemExit(f"{name} not found; set SASS_TOOLKIT to a CUDA toolkit prefix")


def compile_ptx(ptx: str, arch: str = "sm_75") -> bytes:
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "k.ptx"
        cub = Path(td) / "k.cubin"
        src.write_text(ptx)
        r = subprocess.run([find_tool("ptxas"), f"-arch={arch}", "-o", str(cub), str(src)],
                           capture_output=True, text=True)
        if r.returncode:
            raise SystemExit("ptxas failed:\n" + r.stderr)
        return cub.read_bytes()


def text_section(cubin: bytes) -> tuple[str, bytes]:
    shoff, = struct.unpack_from("<Q", cubin, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", cubin, 0x3a)
    sh = [struct.unpack_from("<IIQQQQIIQQ", cubin, shoff + i * shentsize) for i in range(shnum)]
    st = sh[shstrndx]
    names = cubin[st[4]:st[4] + st[5]]
    for s in sh:
        nm = names[s[0]:names.find(b"\0", s[0])].decode()
        if nm.startswith(".text.") and s[1] == 1:
            return nm, cubin[s[4]:s[4] + s[5]]
    raise SystemExit("no .text.<kernel> section")


def disassemble(cubin: bytes) -> list[tuple[str, str]]:
    with tempfile.NamedTemporaryFile(suffix=".cubin", delete=False) as f:
        f.write(cubin)
        path = f.name
    try:
        out = subprocess.run([find_tool("nvdisasm"), "-c", path],
                             capture_output=True, text=True).stdout
    finally:
        os.unlink(path)
    rows = []
    for line in out.splitlines():
        m = re.search(r"/\*([0-9a-f]{4})\*/\s+(.*?);", line)
        if m:
            rows.append((m.group(1), m.group(2).strip()))
    return rows


def pairs(ptx: str) -> list[dict]:
    cubin = compile_ptx(ptx)
    name, blob = text_section(cubin)
    words = [blob[i:i + 16].hex() for i in range(0, len(blob), 16)]
    text = disassemble(cubin)
    return [{"offset": f"0x{off}", "text": t, "bytes": w}
            for (off, t), w in zip(text, words)]


def main(argv: list[str]) -> int:
    json_out = "--json" in argv
    files = [a for a in argv[1:] if not a.startswith("--")]
    if not files:
        print(__doc__)
        return 2
    for f in files:
        rows = pairs(Path(f).read_text())
        if json_out:
            print(json.dumps({f: rows}, indent=1))
        else:
            print(f"== {f}: {len(rows)} instructions")
            for r in rows:
                print(f"  {r['bytes']}  {r['text']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
