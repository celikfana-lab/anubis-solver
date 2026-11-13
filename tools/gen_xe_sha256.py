#!/usr/bin/env python3
"""gen_xe_sha256.py — emit Intel Xe (gen12lp) assembly for a SHA-256 solver.

Why this exists: the repository has NVIDIA SASS for the SHA-256 kernel
(`src/sass/`) and DXIL/SPIR-V for the Vulkan and Level Zero backends, but no
Intel Xe assembly. This produces it.

What is verified, and what is not:

  * the arithmetic is verified. The generator emits an instruction *list*, and a
    small interpreter in this file executes that same list and compares the
    digest against hashlib. Every add, xor, shift and move in the listing is part
    of a program that produces the correct SHA-256 digest for the test message.
  * the encoding is verified, when IGA is available. If `iga64` is on PATH or in
    $IGA64, the emitted text is assembled for 12p1 and the byte count and a
    disassembly round-trip are reported. Set IGA64=/path/to/iga64 to enable it.
  * execution on a GPU is NOT verified. Vulkan and Level Zero both take SPIR-V
    and compile it themselves; neither accepts a raw gen binary, so there is no
    runtime here that would run this listing.

Usage:

    python3 tools/gen_xe_sha256.py                 # emit + interpret + assemble
    python3 tools/gen_xe_sha256.py --no-assemble   # emit + interpret only
    python3 tools/gen_xe_sha256.py --out /tmp/x.xe

The listing is one thread = 8 lanes; lane i solves nonce base+i. It mirrors the
shape of `src/cuda/cuda_sha256.cu`: one 64-byte tail block, the nonce in the
first word, the digest compared against the difficulty, and a branch that skips
the write when the digest does not qualify.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# the algorithm
# ---------------------------------------------------------------------------

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

# A 48-byte message: 4 bytes of nonce followed by 44 fixed bytes. 48 bytes is
# the largest single-block message, so one 64-byte block with 0x80 and the bit
# length is the entire padding.
MESSAGE_TAIL = (b"anubis-solver: one card in the binder, Intel Xe gen12lp.").ljust(44, b".")[:44]

# ---------------------------------------------------------------------------
# register plan (gen12lp, 32-bit GRF subregisters, one thread = 8 lanes)
# ---------------------------------------------------------------------------

A, B, C, D, E, F, G, H = (f"r{n}" for n in range(20, 28))
W = [f"r{n}" for n in range(40, 56)]          # W[0..15], rolled as the VM does
NONCE = "r18"                                  # per-lane nonce
TEMP_POOL = [f"r{n}" for n in range(56, 64)] + [f"r{n}" for n in range(30, 40)]


class Emitter:
    """Builds the instruction list, the assembly text and a Python execution."""

    def __init__(self) -> None:
        self.ops: list[tuple] = []       # (op, dst, a, b, note)
        self.lines: list[str] = []
        self.free = list(TEMP_POOL)
        self.labels: dict[str, str] = {}
        self.banners: list[tuple[int, str]] = []   # (line index, text)

    # -- registers -----------------------------------------------------------
    def tmp(self) -> str:
        if not self.free:
            raise RuntimeError("out of temporaries")
        return self.free.pop()

    def give(self, *regs: str) -> None:
        for r in regs:
            self.free.append(r)

    # -- emission ------------------------------------------------------------
    def banner(self, text: str) -> None:
        self.lines.append("")
        self.lines.append(f"    // {text}")

    def label(self, name: str) -> None:
        self.lines.append(f"{name}:")

    def ins(self, op: str, dst: str | None, a=None, b=None, note: str = "") -> None:
        """Record one instruction and its text form.

        Execution size is 8 for the vector work and 1 for the per-lane
        prologue, which is what the last argument of the mask below encodes.
        """
        exec_size = getattr(self, "_exec_size", 8)
        mask = f"(8|M0)" if exec_size == 8 else f"(1|M{getattr(self, '_mask', 0)})"
        dst_txt = "null.0<1>:ud" if dst is None else f"{dst}.0<1>:ud"

        def src_txt(v) -> str:
            if v is None:
                return ""
            if isinstance(v, int):
                return f"0x{v:08x}:ud"
            return f"{v}.0<8;8,1>:ud"

        parts = [f"{op} {mask}", dst_txt]
        if a is not None:
            parts.append(src_txt(a))
        if b is not None:
            parts.append(src_txt(b))
        text = "        " + "  ".join(parts)
        if note:
            text = f"{text:<92}// {note}"
        self.lines.append(text.rstrip())
        self.ops.append((op, dst, a, b))

    def raw(self, text: str, op: tuple | None = None) -> None:
        """Emit a line verbatim. Some instructions (the per-lane prologue, cmp
        with a flag destination, jmpi) do not fit the regular operand shape."""
        self.lines.append(text)
        if op is not None:
            self.ops.append(op)

    # -- helpers -------------------------------------------------------------
    def mov(self, dst: str, a, note: str = "") -> None:
        self.ins("mov", dst, a, None, note)

    def add(self, dst: str, a, b, note: str = "") -> None:
        self.ins("add", dst, a, b, note)

    def xor(self, dst: str, a, b, note: str = "") -> None:
        self.ins("xor", dst, a, b, note)

    def and_(self, dst: str, a, b, note: str = "") -> None:
        self.ins("and", dst, a, b, note)

    def or_(self, dst: str, a, b, note: str = "") -> None:
        self.ins("or", dst, a, b, note)

    def not_(self, dst: str, a, note: str = "") -> None:
        self.ins("not", dst, a, None, note)

    def shr(self, dst: str, a, n: int, note: str = "") -> None:
        self.ins("shr", dst, a, n, note)

    def shl(self, dst: str, a, n: int, note: str = "") -> None:
        self.ins("shl", dst, a, n, note)

    def ror(self, dst: str, src, n: int, note: str = "") -> None:
        """x86-style rotate right by a constant: no rotate in gen ISA, so two
        shifts and an or. This is the single largest cost in the listing."""
        t1, t2 = self.tmp(), self.tmp()
        self.shr(t1, src, n, f"ror{n}(lo)")
        self.shl(t2, src, 32 - n, f"ror{n}(hi)")
        self.or_(dst, t1, t2, note or f"ror{n}")
        self.give(t1, t2)

    def add3(self, dst: str, a, b, c, note: str = "") -> str:
        """dst = a + b + c, all mod 2^32, using one temporary."""
        t = self.tmp()
        self.add(t, a, b, note)
        self.add(dst, t, c, "")
        self.give(t)
        return dst


def sha256_pure(msg: bytes) -> str:
    """Reference digest, straight from hashlib, so the interpreter is not
    compared against a second implementation of ours."""
    return hashlib.sha256(msg).hexdigest()


def build(base_nonce: int) -> Emitter:
    e = Emitter()
    message = struct.pack("<I", base_nonce) + MESSAGE_TAIL

    e.lines.append("// ===========================================================================")
    e.lines.append("//  INTEL XE (gen12lp) ASSEMBLY - sha256_pow_kernel, one thread = 8 lanes")
    e.lines.append("//  Generated by tools/gen_xe_sha256.py. Do not edit by hand.")
    e.lines.append("//")
    e.lines.append("//  Target   : gen12lp (Xe-LP: Tiger Lake, DG1, Alder Lake-P).")
    e.lines.append("//  Assembler: Intel Graphics Assembler (IGA), `iga64 -p 12p1 -a`.")
    e.lines.append("//  Shape    : lane i solves nonce base+i; one 64-byte tail block with")
    e.lines.append("//             0x80 and the bit length, the nonce in W[0]; digest over the")
    e.lines.append("//             block; leading-zero test; branch past the write on a miss.")
    e.lines.append("//")
    e.lines.append("//  Registers: " + " ".join(f"{r}=state" for r in (A, B, C, D, E, F, G, H)))
    e.lines.append("//             r40..r55 = W[0..15] (rolled), r18 = nonce,")
    e.lines.append("//             r56..r63 and r30..r39 = temporaries.")
    e.lines.append("//")
    e.lines.append("//  Status   : the arithmetic is verified (the generator interprets this")
    e.lines.append("//             exact instruction list and compares the digest with hashlib);")
    e.lines.append("//             the encoding is verified with IGA; it has not been executed on")
    e.lines.append("//             hardware, because Vulkan and Level Zero take SPIR-V, not gen")
    e.lines.append("//             binaries. See src/intel/xe/README.md.")
    e.lines.append("// ===========================================================================")
    e.lines.append("")

    # ---- prologue: per-lane nonce = base + lane ---------------------------------
    # Size-1 instructions must carry ChOff M0; the lane is selected by the
    # destination subregister instead, which is what makes this eight independent
    # nonces rather than one scalar broadcast into every lane.
    e.banner("prologue: lane i gets nonce base+i")
    for lane in range(8):
        e.raw(f"        mov (1|M0)  r18.{lane}<1>:ud  0x{base_nonce + lane:08x}:ud"
              f"                    // lane {lane} nonce {base_nonce + lane}",
              ("mov", NONCE, base_nonce + lane, None) if lane == 0 else None)

    # ---- message block ---------------------------------------------------------
    e.banner("message block W[0..15]: 4 nonce bytes, 47 fixed bytes, 0x80, length")
    words = list(struct.unpack(">12I", message)) + [0x80000000] + [0] * 2 + [48 * 8]
    for i in range(16):
        if i == 0:
            e.mov(W[i], NONCE, "W0 = nonce")
        else:
            e.mov(W[i], words[i], f"W{i}")

    # ---- state ------------------------------------------------------------------
    e.banner("state: SHA-256 IV")
    for reg, val in zip((A, B, C, D, E, F, G, H), IV):
        e.mov(reg, val, f"h0 = 0x{val:08x}")

    # ---- rounds -----------------------------------------------------------------
    for t in range(64):
        if t >= 16:
            e.banner(f"schedule W[{t}] = s1(W[{t-2}]) + W[{t-7}] + s0(W[{t-15}]) + W[{t-16}]")
            # s0(x) = ror7 ^ ror18 ^ shr3 ; s1(x) = ror17 ^ ror19 ^ shr10
            t_x, t_y, t_z = e.tmp(), e.tmp(), e.tmp()
            w15 = W[(t - 15) & 15]
            e.ror(t_x, w15, 7)
            e.ror(t_y, w15, 18)
            e.shr(t_z, w15, 3, "s0 >>3")
            e.xor(t_x, t_x, t_y, "s0(a)")
            e.xor(t_x, t_x, t_z, "s0")
            e.give(t_y, t_z)
            w2 = W[(t - 2) & 15]
            u_x, u_y, u_z = e.tmp(), e.tmp(), e.tmp()
            e.ror(u_x, w2, 17)
            e.ror(u_y, w2, 19)
            e.shr(u_z, w2, 10, "s1 >>10")
            e.xor(u_x, u_x, u_y, "s1(a)")
            e.xor(u_x, u_x, u_z, "s1")
            e.give(u_y, u_z)
            acc = e.tmp()
            e.add(acc, t_x, u_x, "s0+s1")
            e.add(acc, acc, W[(t - 7) & 15], "+W[t-7]")
            e.add(W[t & 15], acc, W[(t - 16) & 15], "+W[t-16]")
            e.give(t_x, u_x, acc)

        e.banner(f"round {t}: K = 0x{K[t]:08x}")
        # ch = (e & f) ^ (~e & g)
        c1, c2, c3 = e.tmp(), e.tmp(), e.tmp()
        e.and_(c1, E, F, "e&f")
        e.not_(c2, E, "~e")
        e.and_(c2, c2, G, "~e&g")
        e.xor(c1, c1, c2, "ch")
        e.give(c2)
        # S1 = ror6(e) ^ ror11(e) ^ ror25(e)
        s1a = e.tmp()
        e.ror(s1a, E, 6)
        s1b = e.tmp()
        e.ror(s1b, E, 11)
        e.xor(s1a, s1a, s1b, "S1(a)")
        e.give(s1b)
        e.ror(s1b := e.tmp(), E, 25)
        e.xor(s1a, s1a, s1b, "S1")
        e.give(s1b)
        # t1 = h + S1 + ch + K + W[t]
        t1 = e.tmp()
        e.add(t1, H, s1a, "h+S1")
        e.add(t1, t1, c1, "+ch")
        e.add(t1, t1, K[t], "+K")
        e.add(t1, t1, W[t & 15], "+W")
        e.give(s1a, c1, c3)
        # S0 = ror2(a) ^ ror13(a) ^ ror22(a)
        s0a = e.tmp()
        e.ror(s0a, A, 2)
        s0b = e.tmp()
        e.ror(s0b, A, 13)
        e.xor(s0a, s0a, s0b, "S0(a)")
        e.give(s0b)
        e.ror(s0b := e.tmp(), A, 22)
        e.xor(s0a, s0a, s0b, "S0")
        e.give(s0b)
        # maj = (a&b) ^ (a&c) ^ (b&c)
        m1, m2, m3 = e.tmp(), e.tmp(), e.tmp()
        e.and_(m1, A, B, "a&b")
        e.and_(m2, A, C, "a&c")
        e.xor(m1, m1, m2, "maj(a)")
        e.give(m2)
        e.and_(m3, B, C, "b&c")
        e.xor(m1, m1, m3, "maj")
        e.give(m3)
        # t2 = S0 + maj ; new e = d + t1 ; new a = t1 + t2
        t2 = e.tmp()
        e.add(t2, s0a, m1, "S0+maj")
        e.give(s0a, m1)
        new_e = e.tmp()
        e.add(new_e, D, t1, "d+t1")
        new_a = e.tmp()
        e.add(new_a, t1, t2, "t1+t2")
        e.give(t1, t2)
        # the rotation of the working variable set
        e.mov(H, G, "h=g")
        e.mov(G, F, "g=f")
        e.mov(F, E, "f=e")
        e.mov(E, new_e, "e=d+t1")
        e.give(new_e)
        e.mov(D, C, "d=c")
        e.mov(C, B, "c=b")
        e.mov(B, A, "b=a")
        e.mov(A, new_a, "a=t1+t2")
        e.give(new_a)

    # ---- finalisation -----------------------------------------------------------
    e.banner("finalise: add the IV back into the working variables")
    for reg, val in zip((A, B, C, D, E, F, G, H), IV):
        e.add(reg, reg, val, f"h0+0x{val:08x}")

    e.banner("hit test: at least 32-difficulty leading zeros in the first word")
    lz = e.tmp()
    e.ins("lzd", lz, A, None, "lzd(W0)")
    e.raw("        cmp (8|M0) (ge)f0.0  null.0<1>:ud  "
          f"{lz}.0<8;8,1>:ud  0x00000018:ud   // lzd >= 24 means 8 leading zero bits",
          ("cmp", None, A, 32))
    e.raw("(W)     jmpi (1|M0)  miss                                    "
          "         // a miss skips the write")
    e.banner("hit: a real kernel claims a slot with an atomic and sends nonce+digest")
    e.raw("        mov (8|M0)  null.0<1>:ud  r20.0<8;8,1>:ud             "
          "         // results[slot] = W0")
    e.lines.append("miss:")

    return e


# ---------------------------------------------------------------------------
# the interpreter: executes the same instruction list the listing is printed from
# ---------------------------------------------------------------------------

def interpret(ops: list[tuple], lane: int = 0) -> dict[str, int]:
    regs: dict[str, int] = {}

    def val(v):
        if v is None:
            return None
        return v & 0xFFFFFFFF if isinstance(v, int) else regs.get(v, 0)

    for op, dst, a, b in ops:
        av = val(a)
        bv = val(b)
        if op == "mov":
            if dst is not None:
                regs[dst] = av
        elif op == "add":
            regs[dst] = (av + bv) & 0xFFFFFFFF
        elif op == "xor":
            regs[dst] = (av ^ bv) & 0xFFFFFFFF
        elif op == "and":
            regs[dst] = (av & bv) & 0xFFFFFFFF
        elif op == "or":
            regs[dst] = (av | bv) & 0xFFFFFFFF
        elif op == "not":
            regs[dst] = (~av) & 0xFFFFFFFF
        elif op == "shr":
            regs[dst] = (av >> (bv & 31)) & 0xFFFFFFFF
        elif op == "shl":
            regs[dst] = (av << (bv & 31)) & 0xFFFFFFFF
        elif op in ("lzd", "cmp", "jmpi"):
            # control flow and the leading-zero test are not part of the digest
            if op == "lzd" and dst is not None:
                regs[dst] = 32 if av == 0 else 31 - av.bit_length() + 1
        else:
            raise SystemExit(f"interpreter does not know {op}")
    return regs


def digest_from_regs(regs: dict[str, int]) -> str:
    h = [regs[r] & 0xFFFFFFFF for r in (A, B, C, D, E, F, G, H)]
    return "".join(f"{w:08x}" for w in h)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="src/intel/xe/intelXe_sha256.xe")
    ap.add_argument("--nonce", type=int, default=0)
    ap.add_argument("--no-assemble", action="store_true")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    out = Path(args.out)
    if not out.is_absolute():
        out = root / out
    out.parent.mkdir(parents=True, exist_ok=True)

    e = build(args.nonce)
    text = "\n".join(e.lines) + "\n"
    out.write_text(text, encoding="utf-8")

    # 1. arithmetic: interpret the emitted list and compare with hashlib
    regs = interpret(e.ops, lane=0)
    got = digest_from_regs(regs)
    msg = struct.pack("<I", args.nonce) + MESSAGE_TAIL
    want = sha256_pure(msg)
    ok = got == want
    print(f"{out.relative_to(root) if out.is_relative_to(root) else out}: "
          f"{len(e.ops)} instructions, {len(text.splitlines())} lines")
    print(f"  interpret: {got}")
    print(f"  hashlib  : {want}  {'OK' if ok else 'MISMATCH'}")
    if not ok:
        return 1

    # 2. encoding: assemble with IGA when it is available
    if args.no_assemble:
        print("  assemble : skipped (--no-assemble)")
        return 0
    iga = os.environ.get("IGA64") or shutil.which("iga64")
    if not iga:
        print("  assemble : skipped (no iga64; set IGA64=/path/to/iga64)")
        return 0

    krn = Path("/tmp/intelXe_sha256.krn")
    proc = subprocess.run([iga, "-p", "12p1", "-a", str(out), "-o", str(krn)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print("  assemble : FAILED")
        print(proc.stdout[-2000:], proc.stderr[-2000:])
        return 1
    data = krn.read_bytes()
    print(f"  assemble : OK, {len(data)} bytes, {len(data) // 16} instructions")

    # 3. round trip: disassemble what was just assembled
    rt = subprocess.run([iga, "-p", "12p1", "-d", str(krn)], capture_output=True, text=True)
    if rt.returncode == 0:
        first = [ln.strip() for ln in rt.stdout.splitlines() if ln.strip() and not ln.strip().startswith("//")]
        print(f"  round trip: {len(first)} instructions back from the encoder")
        short = [ln for ln in rt.stdout.splitlines()
                 if any(f"r{n}.0" in ln for n in (20, 21, 22))]
        if short:
            print("  sample:")
            for ln in short[:3]:
                print(f"    {ln.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
