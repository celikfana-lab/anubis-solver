#!/usr/bin/env python3
"""sassasm — a partial NVIDIA SASS assembler for sm_75 (Turing / Tesla T4).

The encoding is derived empirically, not from documentation: `ptxas` compiles
PTX to a cubin, `nvdisasm` turns the cubin back into text, and the cubin's
`.text` section gives the exact bytes for each instruction. Running the two
sides against each other is the oracle.

What works today:

    MOV Rd, imm32        full 16 bytes reproduced, including the control word
    MOV Rd, c[bank][off] first 12 bytes; the control word varies with schedule

What does not work yet, and why it is not a small gap: the last four bytes of a
SASS instruction are the *control word* — stall counts, yield, read/write
barriers, reuse flags. Those are chosen by ptxas's scheduler from the
dependencies between instructions, not from the instruction text. An assembler
that wants byte-exact output therefore needs a scheduler too, which is why
MaxAs and friends ship one. Until that exists, this assembler produces
instructions that are *semantically* right with a conservative control word.

The remaining instruction families (IADD3, LOP3, SHF, IMAD, LDG/STG, BRA, ...)
each need their own field map. The partial maps measured so far are in
FIELD_MAPS below; they are recorded so the work is not lost, not because they
are implemented.

Usage:

    python3 sassasm/sassasm.py 'MOV R0, 0x2a'          -> hex bytes
    python3 sassasm/selftest.py                        -> verify against ptxas
"""
from __future__ import annotations

import struct
import sys

# Control word for a simple, dependency-free instruction (stall 0, no barriers).
CTRL_PLAIN = bytes.fromhex("00e20f00")
CTRL_CONST = bytes.fromhex("00e40f00")   # and the scheduler may pick another


def _w(*parts: bytes) -> bytes:
    out = b"".join(parts)
    assert len(out) == 16, len(out)
    return out


def mov_imm(dst: int, imm: int) -> bytes:
    """MOV Rd, 0ximm.  Opcode bytes 02 78, dst at +2, immediate at +4."""
    if not 0 <= dst < 256:
        raise ValueError("register out of range")
    return _w(struct.pack("<H", 0x7802), struct.pack("<H", dst),
              struct.pack("<I", imm & 0xFFFFFFFF), b"\x00\x0f\x00\x00", CTRL_PLAIN)


def mov_const(dst: int, bank: int = 0, off: int = 0x28) -> bytes:
    """MOV Rd, c[bank][off].  Opcode bytes 02 7a, index = off/4 at +6.

    The control word is scheduler-chosen; the default here is what ptxas
    picked in the sample this was derived from, so only the first 12 bytes are
    stable."""
    if off % 4:
        raise ValueError("constant offsets are word aligned")
    idx = (bank << 8) | (off // 4)
    # the constant index starts one byte later than the immediate form does:
    # 02 7a | dst | 00 | index(2) | 00 00 0f 00 00 | control
    return _w(struct.pack("<H", 0x7a02), struct.pack("<H", dst),
              b"\x00", struct.pack("<H", idx), b"\x00\x00\x0f\x00\x00", CTRL_CONST)


# Measured field positions for families not implemented yet. Offsets are bytes
# into the 16-byte instruction and `opcode` is the first two bytes in file order
# (so MOV is written 0x7802 but appears as "02 78"). "?" means not established.
FIELD_MAPS = {
    "IADD3": {"opcode": 0x1072, "dst": 2, "src1": 4, "src2": 6, "src3": 8,
              "flags": 10, "note": "0x107a when src2 is a constant"},
    "LOP3.LUT": {"opcode": 0x1272, "dst": 2, "src1": 4, "src2": 6, "src3": 8,
                 "lut": 9, "flags": 10, "note": "LUT immediate sits between src3 and flags"},
    "SHF.L.U32": {"opcode": 0x1978, "dst": 2, "shift": 4, "src1": 8,
                  "flags": 9, "note": "SHF.R uses 0x1978 too; direction in the flags byte"},
    "STG.E": {"opcode": 0x8679, "note": "address is a uniform register pair"},
    "EXIT": {"opcode": 0x794d},
    "NOP": {"opcode": 0x7918},
}


def encode_line(text: str) -> bytes:
    """Encode the two forms this assembler actually supports."""
    t = text.strip().rstrip(";").replace(",", " ").split()
    op = t[0].upper()
    if op == "MOV" and len(t) >= 3:
        dst = int(t[1].lstrip("Rr"))
        src = t[2]
        if src.lower().startswith("c["):
            bank = int(src[src.index("[") + 1:src.index("]")])
            off = int(src[src.index("][") + 2:src.rindex("]")], 0)
            return mov_const(dst, bank, off)
        return mov_imm(dst, int(src, 0))
    raise NotImplementedError(f"{text!r}: only MOV Rd, imm and MOV Rd, c[b][o]")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    for line in argv[1:]:
        for stmt in line.split(";"):
            if not stmt.strip():
                continue
            b = encode_line(stmt)
            print(f"{b.hex()}  // {stmt.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
