#!/usr/bin/env python3
"""selftest.py — check the assembler against ptxas, byte for byte.

For each test case this compiles a tiny PTX kernel whose only live instruction
is the form under test, extracts the bytes ptxas chose, and compares them with
what sassasm.py emits. A mismatch prints both, so the encoder can be fixed
instead of guessed at.

    python3 sassasm/selftest.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import extract  # noqa: E402
from sassasm import mov_const, mov_imm  # noqa: E402

KERNEL = """.version 8.0
.target sm_75
.address_size 64
.visible .entry k(.param .u64 p, .param .u32 a) {{
    .reg .u32 %r<4>;
    .reg .u64 %rd<2>;
    ld.param.u64 %rd1, [p];
    ld.param.u32 %r1, [a];
{body}
    ret;
}}
"""

# 0 is excluded: ptxas canonicalises MOV R0, 0 to MOV R0, RZ, which this
# assembler does not model yet
IMM_CASES = [1, 5, 9, 0x2A, 0x270F, 0x7FFFFFFF, 0xDEADBEEF, 0xFFFFFFFF]


def encode_and_compare(name: str, body: str, want_text: str, ours: bytes) -> bool:
    rows = extract.pairs(KERNEL.format(body=body))
    for r in rows:
        if re.search(want_text, r["text"]):
            theirs = bytes.fromhex(r["bytes"])
            if theirs == ours:
                print(f"  ok    {name:38s} {r['text']}")
                return True
            print(f"  FAIL  {name:38s} {r['text']}")
            print(f"        ptxas {theirs.hex()}")
            print(f"        ours  {ours.hex()}")
            return False
    print(f"  MISS  {name}: ptxas did not emit /{want_text}/")
    for r in rows:
        print(f"        {r['bytes']}  {r['text']}")
    return False


def main() -> int:
    ok = bad = 0
    print("MOV Rd, imm32")
    for imm in IMM_CASES:
        body = f"    mov.b32 %r0, {imm};\n    st.global.u32 [%rd1], %r0;"
        if encode_and_compare(f"MOV R0, 0x{imm:x}", body,
                              r"^MOV R0, 0x[0-9a-f]+$", mov_imm(0, imm)):
            ok += 1
        else:
            bad += 1

    print("MOV Rd, c[0x0][0x28]  (first 12 bytes only: the control word is scheduled)")
    rows = extract.pairs(KERNEL.format(body="    mov.b32 %r0, 1;"))
    hit = [r for r in rows if re.match(r"^MOV R1, c\[0x0\]\[0x28\]$", r["text"])]
    if not hit:
        print("  MISS  MOV R1, c[0x0][0x28]")
        bad += 1
    else:
        theirs = bytes.fromhex(hit[0]["bytes"])[:12]
        ours = mov_const(1, 0, 0x28)[:12]
        if theirs == ours:
            print(f"  ok    MOV R1, c[0x0][0x28] (12/12 bytes)   {hit[0]['text']}")
            ok += 1
        else:
            print(f"  FAIL  ptxas {theirs.hex()}  ours {ours.hex()}")
            bad += 1

    print(f"\n{ok} matched, {bad} failed")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
