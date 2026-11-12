#!/usr/bin/env python3
"""Embed src/levelzero/sha256_pow.spv into src/levelzero/sha256_pow.spv.h."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPV = ROOT / "src" / "sha256_pow.spv"
OUT = ROOT / "src" / "sha256_pow.spv.h"


def main() -> None:
    data = SPV.read_bytes()
    words = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    lines = [
        "    " + ", ".join(f"0x{w:08x}" for w in words[i:i + 8]) + ","
        for i in range(0, len(words), 8)
    ]
    header = (
        "/* Generated from src/levelzero/sha256_pow.cl — do not edit. */\n"
        "static const unsigned int sha256_pow_spv[] = {\n"
        + "\n".join(lines)
        + "\n};\n"
        + f"static const unsigned long sha256_pow_spv_bytes = {len(data)}ul;\n"
    )
    OUT.write_text(header)
    print(f"wrote {OUT} ({len(data)} bytes of SPIR-V)")


if __name__ == "__main__":
    main()
