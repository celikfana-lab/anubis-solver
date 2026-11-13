#!/usr/bin/env python3
"""embed_opencl_kernels.py - regenerate src/opencl/opencl_kernels.h.

The OpenCL backend compiles its kernels from C string literals, so the three
.cl files have to be re-embedded whenever one of them changes. This script is
that step. It writes the header and prints how much it changed, so a no-op run
after an edit to the kernels is visible as a diff instead of silence.

    python3 tools/embed_opencl_kernels.py            # write the header
    python3 tools/embed_opencl_kernels.py --check    # fail if it is stale

The .cl files are shared with the Level Zero backend, which ships precompiled
SPIR-V in src/levelzero/*.spv.h; changing a .cl here does NOT rebuild that
SPIR-V. tools/build_l0_shader.sh does, when spare cycles and a GPU matter.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "opencl" / "opencl_kernels.h"
KERNELS = [
    ("ocl_sha256_src", ROOT / "src" / "opencl" / "sha256_pow.cl"),
    ("ocl_argon2_src", ROOT / "src" / "levelzero" / "argon2id_l0.cl"),
    ("ocl_hashx_src", ROOT / "src" / "levelzero" / "hashx_l0.cl"),
]


def escape(line: str) -> str:
    return line.replace("\\", "\\\\").replace('"', '\\"')


def emit_array(name: str, path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out = [f"static const char {name}[] ="]
    for line in lines:
        out.append(f'    "{escape(line)}\\n"')
        out.append('    ""')
    out.append(";")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 when the header is out of date")
    args = ap.parse_args()

    header = ["/* Generated from the .cl kernels — do not edit. */"]
    for name, path in KERNELS:
        if not path.exists():
            print(f"missing kernel source: {path}", file=sys.stderr)
            return 2
        header.extend(emit_array(name, path))
    text = "\n".join(header) + "\n"

    old = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
    if text == old:
        print(f"{OUT.relative_to(ROOT)} is up to date")
        return 0
    if args.check:
        print(f"{OUT.relative_to(ROOT)} is stale; run tools/embed_opencl_kernels.py",
              file=sys.stderr)
        return 1
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
