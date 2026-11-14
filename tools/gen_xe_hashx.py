#!/usr/bin/env python3
"""gen_xe_hashx.py - emit the HashX kernel as Intel Xe (gen12lp) assembly.

The SHA-256 listing next door was written for one message; this one is written
for one HashX *program*.  A HashX challenge is a program of up to 512
instructions over eight 64-bit registers, so the honest hand-written form is a
JIT: bake the keys and the program into the listing, and the whole thing becomes
straight-line code with no memory reads, no descriptors and no runtime switch.

What is checked, and how:

  1. arithmetic  - this script executes the *emitted instruction list* in a
     Python mirror of gen12lp (one int32 per GRF per lane, eight lanes) and
     compares the 32-byte results with the C reference implementation
     (src/hashx/hashx.c, through tools/xe-hashx-export.c).  A wrong 64-bit
     multiply shows up as a wrong digest, not as an opinion.
  2. encoding    - `iga64 -p 12p1 -a` assembles the listing, if IGA is present.
  3. hardware    - **not done**.  See src/intel/xe/README.md.

The program comes from the reference implementation, not from a second
implementation of the generator: tools/xe-hashx-export.c prints the keys, the
program and the digests for nonces 0..7, and this script consumes all three.

    cc -O2 -o /tmp/hxe tools/xe-hashx-export.c src/hashx/hashx.c -Isrc/hashx
    python3 tools/gen_xe_hashx.py --challenge 0011...eeff --assemble
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

# --------------------------------------------------------------------------- #
#  the HashX program, as exported by the C reference
# --------------------------------------------------------------------------- #

DEMO_CHALLENGE = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

OP_NAMES = {
    0: "UMULH_R", 1: "SMULH_R", 2: "MUL_R", 3: "SUB_R", 4: "XOR_R",
    5: "ADD_RS", 6: "ROR_C", 7: "ADD_C", 8: "XOR_C", 9: "TARGET", 10: "BRANCH",
}


class Program:
    def __init__(self, keys: list[int], ops: list[tuple[int, int, int, int]],
                 digests: list[str]):
        self.keys = keys
        self.ops = ops
        self.digests = digests


def load_program(challenge: str, helper: str) -> Program:
    out = subprocess.run([helper, challenge, "8"], capture_output=True, text=True,
                         check=True).stdout
    keys: list[int] = []
    ops: list[tuple[int, int, int, int]] = []
    digests: list[str] = []
    for line in out.splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "keys":
            keys = [int(x) for x in f[1:5]]
        elif f[0] == "prog":
            ops.append((int(f[1]), int(f[2]), int(f[3]), int(f[4])))
        elif f[0] == "nonce":
            digests.append(f[2])
    if len(keys) != 4 or not ops or len(digests) != 8:
        raise SystemExit("the export helper produced something unexpected")
    return Program(keys, ops, digests)


# --------------------------------------------------------------------------- #
#  the emitter: gen12lp text, and an op list the mirror executes
# --------------------------------------------------------------------------- #

DEBUG_MARKS = os.environ.get("XE_DEBUG_MARKS") == "1"
TEMP_POOL = [f"r{i}" for i in range(40, 112)]   # 72 temporaries, plenty
NONCE_LO, NONCE_HI = "r120", "r121"

# r0..r7 as (lo, hi) register pairs
R = [(f"r{20 + 2 * i}", f"r{21 + 2 * i}") for i in range(8)]


class Emitter:
    """Emit gen12lp text, and keep an op list the Python mirror can run."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.ops: list[tuple] = []
        self.free = list(TEMP_POOL)
        self._pred: str | None = None

    # -- registers -----------------------------------------------------------
    def tmp(self) -> str:
        if not self.free:
            raise RuntimeError("out of temporaries")
        return self.free.pop()

    def give(self, *regs: str) -> None:
        for r in regs:
            self.free.append(r)

    # -- text ----------------------------------------------------------------
    def banner(self, text: str) -> None:
        self.lines.append("")
        self.lines.append(f"    // {text}")

    def label(self, name: str) -> None:
        self.lines.append(f"{name}:")

    def note(self, text: str) -> None:
        self.lines.append(f"    // {text}")

    def _head(self, exec_size: int) -> str:
        return "(8|M0)" if exec_size == 8 else "(1|M0)"

    def ins(self, op: str, dst: str | None, a=None, b=None, note: str = "",
            exec_size: int = 8, pred: str | None = None) -> None:
        """One vector instruction (8 lanes) or scalar (1 lane)."""
        pred = pred or self._pred
        # a vector destination is dense inside one GRF (.0<1>), while a source
        # is lane-strided (.0<8;8,1>). Getting this the wrong way round is what
        # IGA rejects as "invalid destination region".
        dst_txt = "null.0<1>:ud" if dst is None else f"{dst}.0<1>:ud"

        def src(v) -> str:
            if v is None:
                return ""
            if isinstance(v, int):
                return f"0x{v & 0xFFFFFFFF:08x}:ud"
            return f"{v}.0<8;8,1>:ud"

        mask = self._head(exec_size)
        parts = []
        if pred:
            parts.append(f"({pred})")
        parts += [op, mask, dst_txt]
        if a is not None:
            parts.append(src(a))
        if b is not None:
            parts.append(src(b))
        text = "        " + "  ".join(parts)
        if note:
            text = f"{text:<96}// {note}"
        self.lines.append(text.rstrip())
        self.ops.append((op, dst, a, b, exec_size, pred))

    def raw(self, text: str) -> None:
        self.lines.append(text)

    # -- the operations the generator needs ----------------------------------
    def mov(self, dst: str, a, note: str = "") -> None:
        self.ins("mov", dst, a, None, note)

    def add(self, dst: str, a, b, note: str = "") -> None:
        self.ins("add", dst, a, b, note)

    def sub(self, dst: str, a, b, note: str = "") -> None:
        """gen12lp has no plain `sub`: a subtraction is `add` with a negated
        source (`-r5.0<8;8,1>:ud`), which IGA accepts and which is one
        instruction, not two."""
        pred = self._pred
        btxt = (f"-0x{b & 0xFFFFFFFF:08x}:ud" if isinstance(b, int)
                else f"-{b}.0<8;8,1>:ud".replace("--", ""))
        atxt = (f"0x{a & 0xFFFFFFFF:08x}:ud" if isinstance(a, int)
                else f"{a}.0<8;8,1>:ud")
        parts = ([f"({pred})"] if pred else []) + [
            "add", self.tmp_mask(), f"{dst}.0<1>:ud", atxt, btxt]
        text = "        " + "  ".join(parts)
        if note:
            text = f"{text:<96}// {note}"
        self.lines.append(text.rstrip())
        self.ops.append(("sub", dst, a, b, 8, pred))

    def tmp_mask(self) -> str:
        return self._head(8)

    def xor(self, dst: str, a, b, note: str = "") -> None:
        self.ins("xor", dst, a, b, note)

    def and_(self, dst: str, a, b, note: str = "") -> None:
        self.ins("and", dst, a, b, note)

    def or_(self, dst: str, a, b, note: str = "") -> None:
        self.ins("or", dst, a, b, note)

    def not_(self, dst: str, a, note: str = "") -> None:
        self.ins("not", dst, a, None, note)

    def shl(self, dst: str, a, n: int, note: str = "") -> None:
        self.ins("shl", dst, a, n, note)

    def shr(self, dst: str, a, n: int, note: str = "") -> None:
        self.ins("shr", dst, a, n, note)

    def ror(self, dst: str, a, n: int, note: str = "") -> None:
        self.ins("ror", dst, a, n, note)

    def mul(self, dst: str, a, b, note: str = "") -> None:
        self.ins("mul", dst, a, b, note)

    def cmp(self, kind: str, flag: str, a, b, note: str = "") -> None:
        """cmp (8|M0) (kind)f0.0 null a b - sets a whole predicate vector."""
        btxt = (f"0x{b & 0xFFFFFFFF:08x}:ud" if isinstance(b, int)
                else f"{b}.0<8;8,1>:ud")
        text = (f"        cmp (8|M0) ({kind}){flag}.0  null.0<1>:ud  "
                f"{a}.0<8;8,1>:ud  {btxt}")
        if note:
            text = f"{text:<96}// {note}"
        self.lines.append(text.rstrip())
        self.ops.append(("cmp", flag, a, b, 8, kind))

    def predicate(self, pred: str | None) -> None:
        self._pred = pred

    def jmpi(self, target: str, pred: str | None = None, note: str = "") -> None:
        p = pred or self._pred
        text = f"(W)     jmpi {self._head(1)}  {target}"
        if p:
            text = f"        ({p}) jmpi {self._head(8)}  {target}"
        if note:
            text = f"{text:<96}// {note}"
        self.lines.append(text)
        self.ops.append(("jmpi", target, p, None, 8, None))


# --------------------------------------------------------------------------- #
#  64-bit arithmetic on pairs of 32-bit lanes
# --------------------------------------------------------------------------- #

class Word64:
    """A u64 as (lo, hi), each an 8-lane dword vector."""

    __slots__ = ("lo", "hi")

    def __init__(self, lo: str, hi: str):
        self.lo, self.hi = lo, hi


def add64(e: Emitter, d: Word64 | None, a: Word64, b: Word64) -> Word64:
    """d = a + b mod 2^64.

    d may be a itself, so the low half goes to a temporary and the carry is
    read from that: comparing against a register the add already overwrote is
    how the first version of this lost every carry.
    """
    d = d or Word64(e.tmp(), e.tmp())
    t = e.tmp()
    e.add(t, a.lo, b.lo, "lo")
    e.cmp("lt", "f0", t, a.lo, "carry out of the low half")
    e.add(d.hi, a.hi, b.hi, "hi")
    e.predicate("f0.0")
    e.add(d.hi, d.hi, 1, "the carry")
    e.predicate(None)
    e.mov(d.lo, t)
    e.give(t)
    return d


def add64_imm(e: Emitter, d: Word64, a: Word64, imm: int) -> None:
    lo_imm = imm & 0xFFFFFFFF
    hi_imm = (imm >> 32) & 0xFFFFFFFF
    t = e.tmp()
    e.add(t, a.lo, lo_imm, "lo + imm")
    e.add(d.hi, a.hi, hi_imm, "hi + imm.hi")
    if lo_imm:
        e.cmp("lt", "f0", t, a.lo, "carry")
        e.predicate("f0.0")
        e.add(d.hi, d.hi, 1, "carry in")
        e.predicate(None)
    e.mov(d.lo, t)
    e.give(t)


def sub64(e: Emitter, d: Word64 | None, a: Word64, b: Word64) -> Word64:
    """d = a - b mod 2^64; the borrow test runs before either operand is written."""
    d = d or Word64(e.tmp(), e.tmp())
    e.cmp("lt", "f0", a.lo, b.lo, "borrow out of the low half")
    e.sub(d.lo, a.lo, b.lo, "lo")
    e.sub(d.hi, a.hi, b.hi, "hi")
    e.predicate("f0.0")
    e.sub(d.hi, d.hi, 1, "the borrow")
    e.predicate(None)
    return d


def xor64(e: Emitter, d: Word64 | None, a: Word64, b: Word64) -> Word64:
    d = d or Word64(e.tmp(), e.tmp())
    e.xor(d.lo, a.lo, b.lo)
    e.xor(d.hi, a.hi, b.hi)
    return d


def add3_32(e: Emitter, a: str, b: str, c: str) -> tuple[str, str]:
    """a + b + c as 32-bit values; returns (sum, carry) with carry in {0,1,2}."""
    s1, s2 = e.tmp(), e.tmp()
    c1, c2, carry = e.tmp(), e.tmp(), e.tmp()
    e.add(s1, a, b, "a + b")
    e.cmp("lt", "f0", s1, a)
    e.mov(c1, 0)
    e.predicate("f0.0")
    e.mov(c1, 1)
    e.predicate(None)
    e.add(s2, s1, c, "+ c")
    e.cmp("lt", "f0", s2, s1)
    e.mov(c2, 0)
    e.predicate("f0.0")
    e.mov(c2, 1)
    e.predicate(None)
    e.add(carry, c1, c2, "the carry, 0..2")
    e.give(s1, c1, c2)
    return s2, carry


def mul32x32_to_64(e: Emitter, a: str, b: str) -> Word64:
    """Unsigned 32x32 -> 64 with 16-bit limbs.

    a = a1*2^16 + a0, b = b1*2^16 + b0, so
        a*b = A + (B + C)*2^16 + D*2^32,  A=a0*b0 B=a0*b1 C=a1*b0 D=a1*b1
    every one of which is at most 32 bits, so `mul` (low 32) is exact whatever
    the ISA's signedness rules are, and the 64-bit multiply needs no
    high-multiply instruction whose semantics would have to be rediscovered from
    IGC's output. This is the only piece of the file that was wrong three times,
    and each time the self-test below said so in a second.
    """
    a0, a1, b0, b1 = e.tmp(), e.tmp(), e.tmp(), e.tmp()
    e.mov(a0, a)
    e.and_(a0, a0, 0xFFFF, "a & 0xffff")
    e.mov(a1, a)
    e.shr(a1, a1, 16, "a >> 16")
    e.mov(b0, b)
    e.and_(b0, b0, 0xFFFF)
    e.mov(b1, b)
    e.shr(b1, b1, 16)

    p00, p01, p10, p11 = e.tmp(), e.tmp(), e.tmp(), e.tmp()
    e.mul(p00, a0, b0, "A = a0*b0, 32 bits")
    e.mul(p01, a0, b1, "B = a0*b1, 32 bits")
    e.mul(p10, a1, b0, "C = a1*b0")
    e.mul(p11, a1, b1, "D = a1*b1")

    # S = B + C, 33 bits
    sm, sc = e.tmp(), e.tmp()
    e.add(sm, p01, p10, "S = B + C")
    e.cmp("lt", "f0", sm, p01)
    e.mov(sc, 0)
    e.predicate("f0.0")
    e.mov(sc, 1)
    e.predicate(None)

    t, lo, cy, hi, t2 = e.tmp(), e.tmp(), e.tmp(), e.tmp(), e.tmp()
    e.shl(t, sm, 16, "S << 16")
    e.add(lo, p00, t, "lo = A + (S << 16)")
    e.cmp("lt", "f0", lo, p00, "carry out of lo")
    e.mov(cy, 0)
    e.predicate("f0.0")
    e.mov(cy, 1)
    e.predicate(None)
    e.shr(hi, sm, 16)
    e.add(hi, hi, cy)
    e.add(hi, hi, p11, "+ D")
    e.shl(t2, sc, 16, "the 33rd bit of S lands at bit 32")
    e.add(hi, hi, t2)
    e.give(a0, a1, b0, b1, p00, p01, p10, p11, sm, sc, t, cy, t2)
    return Word64(lo, hi)


def mul64_lo(e: Emitter, a: Word64, b: Word64) -> Word64:
    """Low 64 bits of a*b: a.lo*b.lo + ((a.lo*b.hi + a.hi*b.lo) << 32)."""
    ll = mul32x32_to_64(e, a.lo, b.lo)
    lh = mul32x32_to_64(e, a.lo, b.hi)
    hl = mul32x32_to_64(e, a.hi, b.lo)
    lo, hi = e.tmp(), e.tmp()
    e.mov(lo, ll.lo)
    e.add(hi, ll.hi, lh.lo)
    e.add(hi, hi, hl.lo)
    e.give(ll.lo, ll.hi, lh.lo, lh.hi, hl.lo, hl.hi)
    return Word64(lo, hi)


def mul64_hi(e: Emitter, a: Word64, b: Word64) -> Word64:
    """High 64 bits of a*b.

    With P = a.lo*b.lo, Q = a.lo*b.hi, R = a.hi*b.lo, S = a.hi*b.hi (each
    written hi:lo), the product's bits 64..127 are
        carry(P.hi + Q.lo + R.lo) + (Q.hi + R.hi + S.lo) + S.hi*2^32
    where the first term is 0..2 and lands in bit 64.
    """
    ll = mul32x32_to_64(e, a.lo, b.lo)
    lh = mul32x32_to_64(e, a.lo, b.hi)
    hl = mul32x32_to_64(e, a.hi, b.lo)
    hh = mul32x32_to_64(e, a.hi, b.hi)

    x, carry = add3_32(e, ll.hi, lh.lo, hl.lo)      # x, plus the carry into bit 64
    y, ycarry = add3_32(e, lh.hi, hl.hi, hh.lo)     # y, plus the carry into bit 96

    lo, hi = e.tmp(), e.tmp()
    e.add(lo, y, carry, "the low half of the high word")
    e.cmp("lt", "f0", lo, y)
    e.predicate("f0.0")
    e.add(ycarry, ycarry, 1)
    e.predicate(None)
    e.add(hi, hh.hi, ycarry, "the top half")
    e.give(ll.lo, ll.hi, lh.lo, lh.hi, hl.lo, hl.hi, hh.lo, hh.hi, x, carry, y, ycarry)
    return Word64(lo, hi)


def smulh(e: Emitter, a: Word64, b: Word64) -> Word64:
    """Signed high half of a*b.

    smulh = umulh - (a<0 ? b : 0) - (b<0 ? a : 0), all mod 2^64.  The
    corrections are done with a mask rather than a predicated subtract on
    purpose: the subtract needs the carry flag, and a predicated instruction
    whose body clobbers its own predicate is exactly the kind of thing this
    file refuses to contain.
    """
    r = mul64_hi(e, a, b)
    ma, mb, t, z = e.tmp(), e.tmp(), e.tmp(), e.tmp()
    e.mov(z, 0, "a zero, so the negated adds below have two register sources")
    e.shr(ma, a.hi, 31, "sign of a")
    e.sub(ma, z, ma, "all ones if a is negative")
    e.shr(mb, b.hi, 31, "sign of b")
    e.sub(mb, z, mb, "all ones if b is negative")
    ta = Word64(e.tmp(), e.tmp())
    e.and_(ta.lo, b.lo, ma)
    e.and_(ta.hi, b.hi, ma)
    sub64(e, r, r, ta)
    tb = Word64(e.tmp(), e.tmp())
    e.and_(tb.lo, a.lo, mb)
    e.and_(tb.hi, a.hi, mb)
    sub64(e, r, r, tb)
    e.give(ma, mb, t, z, ta.lo, ta.hi, tb.lo, tb.hi)
    return r


def shl64(e: Emitter, d: Word64, a: Word64, n: int) -> None:
    """d = a << n mod 2^64.

    Both halves are built in temporaries and moved at the end: d is usually a
    itself, and writing one half before reading the other is how the first
    version produced registers whose two halves were identical.
    """
    n &= 63
    lo, hi = e.tmp(), e.tmp()
    if n == 0:
        e.mov(lo, a.lo)
        e.mov(hi, a.hi)
    elif n < 32:
        t = e.tmp()
        e.shl(lo, a.lo, n, f"<< {n}")
        e.shr(t, a.lo, 32 - n)
        e.shl(hi, a.hi, n)
        e.or_(hi, hi, t)
        e.give(t)
    elif n == 32:
        e.mov(hi, a.lo, "<< 32")
        e.mov(lo, 0)
    else:
        e.shl(hi, a.lo, n - 32, f"<< {n}")
        e.mov(lo, 0)
    e.mov(d.lo, lo)
    e.mov(d.hi, hi)
    e.give(lo, hi)


def ror64(e: Emitter, d: Word64, a: Word64, n: int) -> None:
    """d = ror(a, n), with the same temps-then-move discipline."""
    n &= 63
    lo, hi = e.tmp(), e.tmp()
    if n == 0:
        e.mov(lo, a.lo)
        e.mov(hi, a.hi)
    elif n == 32:
        e.mov(lo, a.hi, "ror 32")
        e.mov(hi, a.lo)
    elif n < 32:
        t = e.tmp()
        e.shr(lo, a.lo, n, f"ror {n} lo")
        e.shl(t, a.hi, 32 - n)
        e.or_(lo, lo, t)
        e.shr(hi, a.hi, n)
        e.shl(t, a.lo, 32 - n)
        e.or_(hi, hi, t)
        e.give(t)
    else:
        m = 64 - n
        t = e.tmp()
        e.shl(lo, a.lo, m, f"ror {n} is a left rotate by {m}")
        e.shr(t, a.hi, 32 - m)
        e.or_(lo, lo, t)
        e.shl(hi, a.hi, m)
        e.shr(t, a.lo, 32 - m)
        e.or_(hi, hi, t)
        e.give(t)
    e.mov(d.lo, lo)
    e.mov(d.hi, hi)
    e.give(lo, hi)


def rol64(e: Emitter, d: Word64, a: Word64, n: int) -> None:
    """d = rotl(a, n). SIPROUND in hashx.c is written with ROTL."""
    ror64(e, d, a, (64 - n) & 63)


def sipround(e: Emitter, v: list[Word64]) -> None:
    v0, v1, v2, v3 = v
    t = e.tmp()
    add64(e, v0, v0, v1)
    add64(e, v2, v2, v3)
    rol64(e, v1, v1, 13)
    rol64(e, v3, v3, 16)
    e.xor(v1.lo, v1.lo, v0.lo)
    e.xor(v1.hi, v1.hi, v0.hi)
    e.xor(v3.lo, v3.lo, v2.lo)
    e.xor(v3.hi, v3.hi, v2.hi)
    rol64(e, v0, v0, 32)
    add64(e, v2, v2, v1)
    add64(e, v0, v0, v3)
    rol64(e, v1, v1, 17)
    rol64(e, v3, v3, 21)
    e.xor(v1.lo, v1.lo, v2.lo)
    e.xor(v1.hi, v1.hi, v2.hi)
    e.xor(v3.lo, v3.lo, v0.lo)
    e.xor(v3.hi, v3.hi, v0.hi)
    rol64(e, v2, v2, 32)
    e.give(t)


def expand_registers(e: Emitter, keys: list[int]) -> list[Word64]:
    """r[0..7] from the key and the per-lane nonce (hashx_l0.cl's prologue)."""
    v = [Word64(e.tmp(), e.tmp()) for _ in range(4)]
    e.banner("register file from the SipHash key and the lane's nonce")
    # v0..v3 = k0..k3
    e.mov(v[0].lo, keys[0] & 0xFFFFFFFF)
    e.mov(v[0].hi, (keys[0] >> 32) & 0xFFFFFFFF)
    e.mov(v[1].lo, keys[1] & 0xFFFFFFFF)
    e.mov(v[1].hi, (keys[1] >> 32) & 0xFFFFFFFF)
    e.mov(v[2].lo, keys[2] & 0xFFFFFFFF)
    e.mov(v[2].hi, (keys[2] >> 32) & 0xFFFFFFFF)
    e.mov(v[3].lo, keys[3] & 0xFFFFFFFF)
    e.mov(v[3].hi, (keys[3] >> 32) & 0xFFFFFFFF)

    nonce = Word64(NONCE_LO, NONCE_HI)
    e.xor(v[1].lo, v[1].lo, 0xEE, "v1 ^= 0xee")
    e.xor(v[1].hi, v[1].hi, 0)
    e.xor(v[3].lo, v[3].lo, nonce.lo, "v3 ^= nonce")
    e.xor(v[3].hi, v[3].hi, nonce.hi)
    sipround(e, v); sipround(e, v)
    e.xor(v[0].lo, v[0].lo, nonce.lo, "v0 ^= nonce")
    e.xor(v[0].hi, v[0].hi, nonce.hi)
    e.xor(v[2].lo, v[2].lo, 0xEE, "v2 ^= 0xee")
    e.xor(v[2].hi, v[2].hi, 0)
    for _ in range(4):
        sipround(e, v)

    r = [Word64(*x) for x in R]
    for i in range(4):
        e.mov(r[i].lo, v[i].lo)
        e.mov(r[i].hi, v[i].hi)
    e.xor(v[1].lo, v[1].lo, 0xDD, "v1 ^= 0xdd")
    e.xor(v[1].hi, v[1].hi, 0)
    for _ in range(4):
        sipround(e, v)
    for i in range(4):
        e.mov(r[i + 4].lo, v[i].lo)
        e.mov(r[i + 4].hi, v[i].hi)
    for x in v:
        e.give(x.lo, x.hi)
    return r


# --------------------------------------------------------------------------- #
#  the program
# --------------------------------------------------------------------------- #

def emit_op(e: Emitter, r: list[Word64], op: int, dst: int, src: int, imm: int,
            result: Word64 | None) -> Word64 | None:
    """One HashX instruction, and the running `result` the branch tests."""
    name = OP_NAMES.get(op, f"op{op}")
    n = f"r{dst}"
    if op in (0, 1):
        a = r[dst]
        b = r[src]
        if op == 0:
            h = mul64_hi(e, a, b)
        else:
            h = smulh(e, a, b)
        e.banner(f"{n} = {name}({n}, r{src})")
        e.mov(a.lo, h.lo)
        e.mov(a.hi, h.hi)
        e.give(h.lo, h.hi)
        return a
    if op == 2:
        e.banner(f"{n} *= r{src}")
        lo = mul64_lo(e, r[dst], r[src])
        e.mov(r[dst].lo, lo.lo)
        e.mov(r[dst].hi, lo.hi)
        e.give(lo.lo, lo.hi)
    elif op == 3:
        e.banner(f"{n} -= r{src}")
        sub64(e, r[dst], r[dst], r[src])
    elif op == 4:
        e.banner(f"{n} ^= r{src}")
        xor64(e, r[dst], r[dst], r[src])
    elif op == 5:
        e.banner(f"{n} += r{src} << {imm & 63}")
        t = Word64(e.tmp(), e.tmp())
        shl64(e, t, r[src], imm)
        add64(e, r[dst], r[dst], t)
        e.give(t.lo, t.hi)
    elif op == 6:
        e.banner(f"{n} = ror({n}, {imm & 63})")
        ror64(e, r[dst], r[dst], imm)
    elif op == 7:
        val = imm - (1 << 32) if imm >= (1 << 31) else imm   # sign-extended imm32
        e.banner(f"{n} += {val}")
        add64_imm(e, r[dst], r[dst], val & 0xFFFFFFFFFFFFFFFF)
    elif op == 8:
        val = imm - (1 << 32) if imm >= (1 << 31) else imm
        e.banner(f"{n} ^= {val}")
        e.xor(r[dst].lo, r[dst].lo, val & 0xFFFFFFFF)
        e.xor(r[dst].hi, r[dst].hi, (val >> 32) & 0xFFFFFFFF)
    elif op == 9:
        e.banner("TARGET: where the branch comes back to")
    return result


def build(prog: Program, max_ops: int | None = None) -> tuple[Emitter, list[Word64]]:
    e = Emitter()
    ops = prog.ops[: max_ops or len(prog.ops)]

    branch = next((i for i, o in enumerate(ops) if o[0] == 10), None)
    target = None
    for i, o in enumerate(ops[:branch] if branch is not None else []):
        if o[0] == 9:
            target = i
    assert branch is None or target is not None

    header = [
        "// ===========================================================================",
        "//  INTEL XE (gen12lp) ASSEMBLY - hashx_pow, one thread = 8 lanes",
        "//  Generated by tools/gen_xe_hashx.py. Do not edit by hand.",
        "//",
        "//  Target   : gen12lp (Xe-LP: Tiger Lake, DG1, Alder Lake-P).",
        "//  Assembler: Intel Graphics Assembler (IGA), `iga64 -p 12p1 -a`.",
        "//  Shape    : lane i computes HashX(nonce i).  The challenge's SipHash",
        "//             keys and its program are baked in as immediates by the",
        "//             generator, so there are no memory reads and no descriptors:",
        "//             this is the JIT form of the kernel, one listing per",
        "//             challenge program.",
        "//",
        f"//  Program  : {len(ops)} HashX instructions, "
        f"{len([o for o in ops if o[0] == 10])} of them conditional branches.",
        "//  Branches : one every 32 instructions, each jumping back to the start of",
        "//             its own 16-instruction block, at most one ever taken (`be` in",
        "//             hashx.c).  Eight lanes cannot diverge on a jump, so each block",
        "//             runs twice on a program counter of its own and the lanes",
        "//             select; the parts the C would not have executed are undone.",
        f"//  Keys     : {prog.keys}",
        "//  Registers: r20..r35 = r0..r7 (lo, hi pairs of a u64), r120 = nonce lo,",
        "//             r121 = nonce hi, r40..r111 = temporaries.",
        "//",
        "//  Status   : the arithmetic is verified (this generator executes the",
        "//             emitted instruction list in a Python mirror of gen12lp and",
        "//             compares all 8 digests with src/hashx/hashx.c); the encoding",
        "//             is verified with IGA; it has not run on hardware.  See",
        "//             src/intel/xe/README.md, which is also where the reasons live.",
        "// ===========================================================================",
        "",
    ]
    e.lines.extend(header)

    # prologue: nonce = lane index (base 0), so lane i hashes nonce i
    e.banner("prologue: lane i hashes nonce i (base is baked in as 0)")
    for lane in range(8):
        e.raw(f"        mov (1|M0)  {NONCE_LO}.{lane}<1>:ud  0x{lane:08x}:ud"
              f"                    // lane {lane} nonce {lane}")
        e.raw(f"        mov (1|M0)  {NONCE_HI}.{lane}<1>:ud  0x00000000:ud")
    e.ops.append(("scalar_noncelo", None, None, None, 1, None))
    e.ops.append(("scalar_noncehi", None, None, None, 1, None))

    r = expand_registers(e, prog.keys)
    e.ops.append(("mark", "expand", None, None, 8, None))

    # ---- the program ---------------------------------------------------------
    # A HashX program has a conditional branch every 32 instructions, each one
    # jumping back to the start of its own 16-instruction block, and `be`
    # (branch_enable) means at most one of them is ever taken.  Eight lanes
    # cannot take different branches with a real jump, and they do take
    # different ones, so each block is executed twice: once on the straight
    # path, and once on a copy guarded by that block's own predicate.  A lane
    # keeps the copy when its predicate fired and it had not already fired --
    # which is exactly what the C's single `be` flag means, per lane.
    def run_range(start: int, end: int, result: Word64 | None) -> Word64 | None:
        for i in range(start, end):
            e.note(f"[{i:3d}] {OP_NAMES.get(ops[i][0], ops[i][0])}")
            result = emit_op(e, r, *ops[i], result)
            if DEBUG_MARKS:
                e.ops.append(("mark", f"op{i}", None, None, 8, None))
        return result

    branches = [i for i, o in enumerate(ops) if o[0] == 10]
    if not branches:
        e.banner("no branch in this program: the straight line is the program")
        run_range(0, len(ops), None)
    else:
        fired = e.tmp()
        e.mov(fired, 0, "no lane has taken a branch yet")
        cursor = 0
        result: Word64 | None = None
        for bi in branches:
            target = max((i for i in range(bi) if ops[i][0] == 9), default=None)
            if target is None:
                raise SystemExit(f"branch at {bi} with no TARGET before it")
            result = run_range(cursor, bi, result)
            imm = ops[bi][3]
            e.banner(f"branch [{bi}]: ((result & 0x{imm:08x}) == 0) re-runs "
                     f"[{target + 1}..{bi - 1}] (the C sets i = target, then ++i)")
            pred = e.tmp()
            if result is None:
                e.note("no UMULH/SMULH before this branch: result is 0, every lane fires")
                e.mov(pred, 0xFFFFFFFF)
            else:
                t = e.tmp()
                e.and_(t, result.lo, imm, "result & imm")
                e.cmp("eq", "f1", t, 0, "the branch test")
                e.give(t)
                e.mov(pred, 0)
                e.ins("mov", pred, 0xFFFFFFFF, None, "all ones where the test holds",
                      pred="f1.0")
            notfired = e.tmp()
            apply = e.tmp()
            e.not_(notfired, fired, "~fired")
            e.and_(apply, pred, notfired, "apply = pred & ~fired")
            e.cmp("ne", "f1", apply, 0, "does any lane take this one?")
            e.give(notfired)

            touched = sorted({ops[i][1] for i in range(target + 1, bi)
                              if ops[i][0] in (0, 1, 2, 3, 4, 5, 6, 7, 8)})
            e.note(f"registers the re-run touches: "
                   f"{', '.join('r' + str(i) for i in touched) or '(none)'}")
            saved = {i: Word64(e.tmp(), e.tmp()) for i in touched}
            for i, w in saved.items():
                e.mov(w.lo, r[i].lo, f"save r{i}.lo")
                e.mov(w.hi, r[i].hi, f"save r{i}.hi")
            # the block runs once more, for every lane; the lanes that did not
            # take this branch are put back afterwards, which is the SIMD form
            # of "the other lanes never executed this part"
            scratch = run_range(target + 1, bi, None)      # result stays the straight path's
            restore = e.tmp()
            e.not_(restore, apply, "~apply: the lanes that keep the straight path")
            e.cmp("ne", "f1", restore, 0)
            e.give(restore)
            for i, w in saved.items():
                e.ins("mov", r[i].lo, w.lo, None, f"restore r{i}.lo", pred="f1.0")
                e.ins("mov", r[i].hi, w.hi, None, f"restore r{i}.hi", pred="f1.0")
                e.give(w.lo, w.hi)
            e.or_(fired, fired, pred, "this lane has now had its one branch")
            e.give(pred, apply)
            cursor = bi + 1
            (void := scratch)
        run_range(cursor, len(ops), result)
        e.give(fired)

    # finalization: keys back in, one SIPROUND per half, xor and store nothing
    e.ops.append(("mark", "post", None, None, 8, None))
    e.banner("finalization: r[0] += k0, r[1] += k1, r[6] += k2, r[7] += k3")
    add64_imm(e, r[0], r[0], prog.keys[0])
    add64_imm(e, r[1], r[1], prog.keys[1])
    add64_imm(e, r[6], r[6], prog.keys[2])
    add64_imm(e, r[7], r[7], prog.keys[3])
    e.banner("one SipRound over r[0..3] and one over r[4..7]")
    sipround(e, [r[0], r[1], r[2], r[3]])
    sipround(e, [r[4], r[5], r[6], r[7]])
    e.banner("the 32-byte digest is r[0]^r[4] .. r[3]^r[7], little-endian")
    for i in range(4):
        e.xor(r[i].lo, r[i].lo, r[i + 4].lo)
        e.xor(r[i].hi, r[i].hi, r[i + 4].hi)

    e.lines.append("")
    e.raw("(W)     send.ts (1|M0)  null  r127  null  0x0  0x02000010  {EOT}          "
          "// end of thread")
    e.ops.append(("eot", None, None, None, 1, None))
    return e, r


# --------------------------------------------------------------------------- #
#  the Python mirror: eight lanes of int32, one per GRF
# --------------------------------------------------------------------------- #

class Mirror:
    def __init__(self) -> None:
        self.regs: dict[str, list[int]] = {}
        self.flags: dict[str, list[bool]] = {}
        self.nonce = [0] * 8

    def set(self, name: str, lane: int, v: int) -> None:
        self.regs.setdefault(name, [0] * 8)[lane] = v & 0xFFFFFFFF

    def get(self, name: str) -> list[int]:
        return self.regs.setdefault(name, [0] * 8)

    def run(self, ops: list[tuple], marks: dict | None = None) -> None:
        scalar_lane = 0
        for op in ops:
            kind = op[0]
            if kind == "mark":
                if marks is not None:
                    marks.setdefault(op[1], {})
                    marks[op[1]][""] = {k: list(v) for k, v in self.regs.items()}
                continue
            if kind == "scalar_noncelo":
                scalar_lane = 0
                self.nonce = [i for i in range(8)]
                for lane in range(8):
                    self.set(NONCE_LO, lane, lane)
                continue
            if kind == "scalar_noncehi":
                for lane in range(8):
                    self.set(NONCE_HI, lane, 0)
                continue
            if kind == "eot":
                break
            _, dst, a, b, exec_size, pred = op
            if kind == "cmp":
                # (kind, flag, a, b)
                _, flag, a, b, _, ckind = op
                av, bv = self.get(a), (b if isinstance(b, int) else self.get(b))
                vals = [av[i] & 0xFFFFFFFF for i in range(8)]
                bvals = [bv[i] & 0xFFFFFFFF for i in range(8)] if not isinstance(b, int) else [bv & 0xFFFFFFFF] * 8
                if ckind == "lt":
                    self.flags[flag] = [vals[i] < bvals[i] for i in range(8)]
                elif ckind == "eq":
                    self.flags[flag] = [vals[i] == bvals[i] for i in range(8)]
                elif ckind == "ne":
                    self.flags[flag] = [vals[i] != bvals[i] for i in range(8)]
                elif ckind == "ge":
                    self.flags[flag] = [vals[i] >= bvals[i] for i in range(8)]
                continue
            if kind == "jmpi":
                continue
            active = [True] * 8
            if pred:
                flag = pred.split(".")[0]
                active = self.flags.get(flag, [False] * 8)
            if exec_size == 1:
                active = [i == scalar_lane for i in range(8)]
            av = self.get(a) if isinstance(a, str) else None
            bv = self.get(b) if isinstance(b, str) else None
            d = self.get(dst)
            for i in range(8):
                if not active[i]:
                    continue
                x = av[i] if av is not None else (a if isinstance(a, int) else 0)
                if b is None:
                    y = 0
                elif isinstance(b, int):
                    y = b & 0xFFFFFFFF
                else:
                    y = bv[i]
                if kind == "mov":
                    v = x
                elif kind == "add":
                    v = x + y
                elif kind == "sub":
                    v = x - y
                elif kind == "xor":
                    v = x ^ y
                elif kind == "and":
                    v = x & y
                elif kind == "or":
                    v = x | y
                elif kind == "not":
                    v = ~x
                elif kind == "shl":
                    v = x << (y & 31)
                elif kind == "shr":
                    v = x >> (y & 31)
                elif kind == "ror":
                    n = y & 31
                    v = ((x >> n) | (x << (32 - n))) if n else x
                elif kind == "mul":
                    v = x * y
                else:
                    raise SystemExit(f"the mirror does not know {kind}")
                d[i] = v & 0xFFFFFFFF

    def digest(self, r: list[Word64]) -> list[str]:
        out = []
        for lane in range(8):
            words = []
            for i in range(4):
                lo = self.get(r[i].lo)[lane]
                hi = self.get(r[i].hi)[lane]
                words.append(lo | (hi << 32))
            out.append(b"".join(w.to_bytes(8, "little") for w in words).hex())
        return out


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #

def check_stages(prog: Program, e: Emitter, r: list[Word64], challenge: str) -> int:
    """Compare r[0..7] with the C interpreter after expansion and after the program."""
    helper = "/tmp/hxs"
    if not os.path.exists(helper):
        subprocess.run(["cc", "-O2", "-o", helper, "tools/xe-hashx-stages.c",
                        "-Isrc/hashx"], check=True)
    out = subprocess.run([helper, challenge, "8"], capture_output=True, text=True,
                         check=True).stdout
    want: dict[str, list[list[int]]] = {"expand": [], "post": []}
    for line in out.splitlines():
        f = line.split()
        if f and f[0] in want:
            want[f[0]].append([int(x, 16) for x in f[2:10]])
    marks: dict = {}
    m = Mirror()
    m.run(e.ops, marks)
    bad = 0
    for stage in ("expand", "post"):
        snap = marks[stage][""]
        for lane in range(8):
            got = [snap[r[i].lo][lane] | (snap[r[i].hi][lane] << 32) for i in range(8)]
            if got != want[stage][lane]:
                bad += 1
                if bad <= 4:
                    print(f"  {stage} lane {lane}:")
                    for i in range(8):
                        flag = "" if got[i] == want[stage][lane][i] else "   <-- differs"
                        print(f"    r{i}: {got[i]:016x} want {want[stage][lane][i]:016x}{flag}")
    if bad:
        print(f"{bad} register file(s) differ")
        return 1
    print("the register file matches src/hashx/hashx.c after expansion and after the program")
    return 0


def selftest() -> int:
    """Check every 64-bit primitive against Python's own integers."""
    import random
    rng = random.Random(1234)
    M = (1 << 64) - 1
    cases = [(0, 0), (1, 1), (M, 1), (0x123456789ABCDEF0, 0x0FEDCBA987654321)]
    cases += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(6)]
    bad = 0
    for a, b in cases:
        e = Emitter()
        A = Word64(e.tmp(), e.tmp())
        B = Word64(e.tmp(), e.tmp())
        e.mov(A.lo, a & 0xFFFFFFFF)
        e.mov(A.hi, a >> 32)
        e.mov(B.lo, b & 0xFFFFFFFF)
        e.mov(B.hi, b >> 32)
        outs: dict[str, Word64] = {}
        outs["add"] = add64(e, None, A, B)
        outs["sub"] = sub64(e, None, A, B)
        outs["xor"] = xor64(e, None, A, B)
        outs["mullo"] = mul64_lo(e, A, B)
        outs["mulhi"] = mul64_hi(e, A, B)
        sh = Word64(e.tmp(), e.tmp())
        shl64(e, sh, A, 17)
        outs["shl17"] = sh
        for rot in (1, 13, 16, 17, 21, 31, 32, 33, 47, 63):
            rr = Word64(e.tmp(), e.tmp())
            ror64(e, rr, A, rot)
            outs[f"ror{rot}"] = rr
        sa = a - (1 << 64) if a >> 63 else a
        sb = b - (1 << 64) if b >> 63 else b
        shi = smulh(e, A, B)
        outs["smulh"] = shi

        m = Mirror()
        m.run(e.ops)

        def get(w: Word64) -> int:
            return m.get(w.lo)[0] | (m.get(w.hi)[0] << 32)

        want = {
            "add": (a + b) & M,
            "sub": (a - b) & M,
            "xor": a ^ b,
            "mullo": (a * b) & M,
            "mulhi": (a * b >> 64) & M,
            "shl17": (a << 17) & M,
            **{f"ror{rot}": ((a >> rot) | (a << (64 - rot))) & M if rot % 64 else a
               for rot in (1, 13, 16, 17, 21, 31, 32, 33, 47, 63)},
            "smulh": (sa * sb >> 64) & M,
        }
        for k, w in outs.items():
            got = get(w)
            if got != want[k]:
                print(f"  {k}: a={a:#018x} b={b:#018x} got {got:#018x} want {want[k]:#018x}")
                bad += 1
    if bad:
        print(f"selftest: {bad} wrong result(s)")
        return 1
    print(f"selftest: all 64-bit primitives agree with Python over {len(cases)} cases")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--challenge", default=DEMO_CHALLENGE,
                    help="challenge hex (randomData) to build the listing for")
    ap.add_argument("--emit", default="src/intel/xe/intelXe_hashx.xe",
                    help="where to write the listing (default %(default)s)")
    ap.add_argument("--helper", default="/tmp/hxe",
                    help="tools/xe-hashx-export.c, compiled (default %(default)s)")
    ap.add_argument("--max-ops", type=int, default=None,
                    help="stop after this many instructions (for quick iteration)")
    ap.add_argument("--assemble", action="store_true",
                    help="run iga64 on the listing and report the size")
    ap.add_argument("--no-verify", action="store_true", help="skip the mirror check")
    ap.add_argument("--stages", action="store_true",
                    help="compare the register file after expansion and after the "
                         "program against tools/xe-hashx-stages.c")
    ap.add_argument("--selftest", action="store_true",
                    help="check the 64-bit primitives against Python and exit")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not os.path.exists(args.helper):
        print(f"building {args.helper} from tools/xe-hashx-export.c", file=sys.stderr)
        subprocess.run(["cc", "-O2", "-o", args.helper, "tools/xe-hashx-export.c",
                        "src/hashx/hashx.c", "-Isrc/hashx"], check=True)

    prog = load_program(args.challenge, args.helper)
    e, r = build(prog, args.max_ops)

    text = "\n".join(e.lines) + "\n"
    with open(args.emit, "w") as f:
        f.write(text)
    insn = len([l for l in e.lines if "        " in l and not l.lstrip().startswith("//")])
    print(f"{args.emit}: {insn} instructions, {len(text)} bytes of text, "
          f"{len(prog.ops)} program ops")

    if args.stages:
        return check_stages(prog, e, r, args.challenge)

    if not args.no_verify:
        m = Mirror()
        m.run(e.ops)
        got = m.digest(r)
        want = prog.digests if args.max_ops is None else None
        if want is None:
            print("partial listing (--max-ops): digest check skipped")
        else:
            bad = [i for i in range(8) if got[i] != want[i]]
            if bad:
                for i in bad:
                    print(f"  lane {i}: got {got[i]}\n           want {want[i]}")
                print("MISMATCH")
                return 1
            print(f"all 8 digests match src/hashx/hashx.c (nonce 0..7)")

    if args.assemble:
        iga = os.environ.get("IGA64") or shutil.which("iga64")
        if not iga:
            print("no iga64 on PATH and no IGA64 set; skipping the encoding check",
                  file=sys.stderr)
        else:
            with tempfile.TemporaryDirectory() as td:
                out = os.path.join(td, "hashx.krn")
                p = subprocess.run([iga, "-p", "12p1", "-a", args.emit, "-o", out],
                                   capture_output=True, text=True)
                if p.returncode != 0:
                    print(p.stdout[-2000:])
                    print(p.stderr[-2000:])
                    return 1
                size = os.path.getsize(out)
                print(f"iga64: assembled, {size} bytes ({size // 16} instructions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
