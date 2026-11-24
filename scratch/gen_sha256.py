#!/usr/bin/env python3
"""Generate SHA-256 as a pure Scratch 3 project (.sb3) -- no extensions, no JS.

Three things make this port interesting, and all three were measured against
the real scratch-vm rather than assumed.

1. Scratch has no bitwise operators
-----------------------------------
You get ``+ - * / mod`` and ``floor``.  Nothing else.  A 32-bit word is just an
exact double (every integer below 2**53 is exact), so most of SHA-256 is plain
arithmetic::

    add mod 2**32   (a + b) mod 4294967296                            exact
    rotr(x, n)      floor(x / 2**n) + (x mod 2**n) * 2**(32-n)        exact
    shr(x, n)       floor(x / 2**n)                                   exact
    not32(x)        4294967295 - x                                    exact

xor/and/or have no arithmetic closed form, so they are table lookups: split a
word into limbs, index a 2**L x 2**L table with the pair, reassemble::

    xor32(a,b) = sum_k XOR_T[((a>>Lk) & m)*m + ((b>>Lk) & m)] * m**k

L=4 needs a 256-entry table and 8 lookups; L=8 needs 65536 entries and 4.

2. Scratch procedures cannot return a value
-------------------------------------------
``procedures_call`` is a stack block: putting one in an input slot runs it and
yields nothing.  Verified -- the callee ran, its global held 42, the receiving
variable was ``undefined``.  So there are no functions, only globals: a call is
a statement that leaves its result in ``IRES``, and expressions containing
calls must be flattened into statements with temporaries (``Fn`` below).

3. A statement costs about a microsecond
---------------------------------------
Measured (`scratch/tools/bench_ops.py`): 1.0-1.3 us per statement in scratch-vm,
and a custom block call adds ~2 us.  So the generator bakes every constant it
can: rot/shift/add are emitted as nested *reporters* with literal powers of two
(no call, no temporary), and the bitwise lookup loop is unrolled so each limb is
a single ``change IRES by`` statement.  That turned a 25-statement xor into a
5-statement one, and a 64-byte block from ~55 ms into single-digit ms.

Usage
-----
    python3 scratch/gen_sha256.py                    # 4-bit limbs -> sha256.sb3
    python3 scratch/gen_sha256.py --limb 8 --out ... # 8-bit limbs, ~2x fewer statements
    node scratch/tools/run_sb3.mjs scratch/build/sha256.sb3 '[97,98,99]'
    python3 scratch/tools/verify_sha256.py           # against hashlib

The project has a stage list ``MSG`` (bytes) and a variable ``OUT_HEX`` (the
digest).  Green flag hashes MSG -- which is copied into ``BUF`` first, so the
flag can be pressed repeatedly.  ``DONE`` becomes 1 when the digest is complete,
which is what the headless harness waits on.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))
from sb3 import BLANK_SVG, Project  # noqa: E402

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

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

TWO32 = 4294967296
MASK32 = 4294967295
MSG_DEFAULT = [97, 98, 99]  # "abc"
TEMP_SLOTS = 8


# ---------------------------------------------------------------------------
# expression nodes: ("lit", n) ("var", name) ("item", list, idx) ("raw", id)
#                   ("op", "add"|..., [args]) ("call", proccode, [args])


def lit(v):
    return ("lit", v)


def var(v):
    return ("var", v)


def item(lst, idx):
    return ("item", lst, idx)


def raw(block_id):
    return ("raw", block_id)


def op(kind, *args):
    return ("op", kind, list(args))


def call(proc, *args):
    return ("call", proc, list(args))


def joined(*parts):
    """Fold parts into one left-nested join, in order (bubble text)."""
    out = parts[0]
    for part in parts[1:]:
        out = op("join", out, part)
    return out


def not32(e):
    return op("sub", lit(MASK32), e)


class Fn:
    """Builds one procedure body, flattening calls into statements."""

    def __init__(self, st):
        self.st = st
        self.out = []
        self.pool = 0

    # ---- value materialisation ----------------------------------------
    def value(self, e):
        kind = e[0]
        if kind == "lit":
            return e[1]
        if kind == "raw":
            return e[1]
        if kind == "var":
            return self.st.getv(e[1])
        if kind == "item":
            return self.st.item(e[1], self.value(e[2]))
        if kind == "op":
            vals = [self.value(a) for a in e[2]]
            return getattr(self.st, e[1])(*vals)
        if kind == "call":
            vals = [self.value(a) for a in e[2]]
            self.out.append(self.st.call_proc(e[1], vals))
            name = self.tmp()
            self.out.append(self.st.setv(name, self.st.getv("IRES")))
            return self.st.getv(name)
        raise ValueError("bad node %r" % (e,))

    def tmp(self):
        self.pool += 1
        if self.pool > TEMP_SLOTS:
            raise RuntimeError("expression too deep: raise TEMP_SLOTS")
        name = "E%d" % self.pool
        self.st.var(name, 0)
        return name

    # ---- statements ----------------------------------------------------
    def bind(self, target, e):
        """target <- e, reading IRES directly when e is a single call."""
        self.pool = 0
        if e[0] == "call":
            vals = [self.value(a) for a in e[2]]
            self.out.append(self.st.call_proc(e[1], vals))
            self.out.append(self.st.setv(target, self.st.getv("IRES")))
        else:
            self.out.append(self.st.setv(target, self.value(e)))

    set = bind

    def setitem(self, lst, idx, e):
        self.pool = 0
        self.out.append(self.st.replace(lst, self.value(idx), self.value(e)))

    def addto(self, lst, e):
        self.pool = 0
        self.out.append(self.st.addto(lst, self.value(e)))

    def change(self, name, e):
        self.pool = 0
        self.out.append(self.st.changev(name, self.value(e)))

    def say(self, e):
        """Speech bubble whose text is an expression (pure reporters only)."""
        self.pool = 0
        self.out.append(self.st.say(self.value(e)))

    def do(self, block):
        self.pool = 0
        self.out.append(block)


# ---------------------------------------------------------------------------
# 32-bit operations.  Everything except the bitwise ones is a pure reporter
# expression: no procedure, no temporary, constants already folded.


def rotr(x, n):
    hi = 1 << n          # 2**n
    lo = 1 << (32 - n)   # 2**(32-n)
    return op("add", op("floor", op("div", x, lit(hi))),
              op("mul", op("mod", x, lit(hi)), lit(lo)))


def shr(x, n):
    return op("floor", op("div", x, lit(1 << n)))


def add32(a, b):
    return op("mod", op("add", a, b), lit(TWO32))


def xor(a, b):
    return call("xor32 %s %s", a, b)


def and_(a, b):
    return call("and32 %s %s", a, b)


def or_(a, b):
    return call("or32 %s %s", a, b)


def big_sigma0(x):
    return xor(xor(rotr(x, 2), rotr(x, 13)), rotr(x, 22))


def big_sigma1(x):
    return xor(xor(rotr(x, 6), rotr(x, 11)), rotr(x, 25))


def small_sigma0(x):
    return xor(xor(rotr(x, 7), rotr(x, 18)), shr(x, 3))


def small_sigma1(x):
    return xor(xor(rotr(x, 17), rotr(x, 19)), shr(x, 10))


def ch(e, f, g):
    return or_(and_(e, f), and_(not32(e), g))


def maj(a, b, c):
    return or_(and_(a, b), and_(c, or_(a, b)))


# ---------------------------------------------------------------------------


def bitwise_proc(st, proc, table, limb):
    """xor32/and32/or32: one statement per limb, constants already folded."""
    stride = 1 << limb
    d, _ = st.def_proc(proc, ["a", "b"])
    body = [st.setv("IRES", 0)]
    for k in range(32 // limb):
        scale = stride ** k
        idx = st.add(
            st.mul(st.mod(st.floor(st.div(st.arg("a"), scale)), stride), stride),
            st.mod(st.floor(st.div(st.arg("b"), scale)), stride),
        )
        body.append(st.changev("IRES", st.mul(st.item(table, st.add(idx, 1)), scale)))
    st.chain(d, *body)
    st.script(d)


def gen(limb=4, out_path=None):
    stride = 1 << limb
    p = Project()
    st = p.stage()
    p.costume(st, "blank", BLANK_SVG, 1, 1)

    for name in ("A", "B", "C", "D", "E", "F", "G", "H",
                 "S1", "S2", "CH", "MJ", "T1", "T2",
                 "MSGLEN", "NBLK", "BLK", "R", "I",
                 "OUT_HEX", "DONE", "IRES",
                 "NONCE", "DIFF", "FOUND", "Z", "HPS", "ETA", "ANS", "TMP2",
                 "DIG0", "DIG1", "ELAPSED"):
        st.var(name, 0)
    for i in range(1, TEMP_SLOTS + 1):
        st.var("E%d" % i, 0)

    st.lst("MSG", MSG_DEFAULT)
    st.lst("CHAL", [])
    st.lst("SRC", [])
    st.lst("BUF", [])
    st.lst("W", [0] * 64)
    st.lst("HS", IV)
    st.lst("K", K)
    st.lst("HEXD", list("0123456789abcdef"))
    st.lst("HEXDU", list("0123456789ABCDEF"))
    st.lst("POW2", [2 ** i for i in range(33)])
    entries = stride * stride
    st.lst("XOR_T", [float((i // stride) ^ (i % stride)) for i in range(entries)])
    st.lst("AND_T", [float((i // stride) & (i % stride)) for i in range(entries)])
    st.lst("OR_T", [float((i // stride) | (i % stride)) for i in range(entries)])
    p.monitor(st, "OUT_HEX", "large", 5, 5)
    p.monitor(st, "NONCE", "default", 5, 80)
    p.monitor(st, "HPS", "default", 5, 110)

    # The cat has to own the blocks: `say` and `ask and wait` act on the sprite
    # they live in, and a sprite cannot call the stage's custom blocks.  So the
    # variables stay global (declared above, on the stage) and every block below
    # is emitted into the sprite, which borrows the stage's name -> id maps.
    cat = p.sprite("Mascot")
    cat.size = 55  # the costume is 360 px tall; the stage is 360 px
    here = os.path.dirname(os.path.abspath(__file__))
    p.costume_png(cat, "mascot", os.path.join(here, "assets", "mascot.png"))
    cat._varname = st._varname
    cat._listname = st._listname
    st = cat

    bitwise_proc(st, "xor32 %s %s", "XOR_T", limb)
    bitwise_proc(st, "and32 %s %s", "AND_T", limb)
    bitwise_proc(st, "or32 %s %s", "OR_T", limb)

    # ---- one 64-byte block ---------------------------------------------
    def block_body():
        f = Fn(st)
        f.set("I", lit(1))
        inner = Fn(st)
        base = op("mul", var("BLK"), lit(64))
        word = op("add",
                  op("add",
                     op("mul", item("BUF", op("sub", op("add", base, op("mul", var("I"), lit(4))), lit(3))), lit(16777216)),
                     op("mul", item("BUF", op("sub", op("add", base, op("mul", var("I"), lit(4))), lit(2))), lit(65536))),
                  op("add",
                     op("mul", item("BUF", op("sub", op("add", base, op("mul", var("I"), lit(4))), lit(1))), lit(256)),
                     item("BUF", op("add", base, op("mul", var("I"), lit(4))))))
        inner.setitem("W", var("I"), word)
        inner.change("I", lit(1))
        f.do(st.repeat(16, st.chain(*inner.out)))

        f.set("I", lit(17))
        inner = Fn(st)
        inner.set("T1", small_sigma1(item("W", op("sub", var("I"), lit(2)))))
        inner.set("T1", add32(var("T1"), item("W", op("sub", var("I"), lit(7)))))
        inner.set("T1", add32(var("T1"), small_sigma0(item("W", op("sub", var("I"), lit(15))))))
        inner.set("T1", add32(var("T1"), item("W", op("sub", var("I"), lit(16)))))
        inner.setitem("W", var("I"), var("T1"))
        inner.change("I", lit(1))
        f.do(st.repeat_until(st.eq(st.getv("I"), 65), st.chain(*inner.out)))

        for i, name in enumerate("ABCDEFGH"):
            f.set(name, item("HS", lit(i + 1)))
        f.set("R", lit(0))
        inner = Fn(st)
        inner.set("S1", big_sigma1(var("E")))
        inner.set("S2", big_sigma0(var("A")))
        inner.set("CH", ch(var("E"), var("F"), var("G")))
        inner.set("MJ", maj(var("A"), var("B"), var("C")))
        inner.set("T1", add32(var("H"), var("S1")))
        inner.set("T1", add32(var("T1"), var("CH")))
        inner.set("T1", add32(var("T1"), item("K", op("add", var("R"), lit(1)))))
        inner.set("T1", add32(var("T1"), item("W", op("add", var("R"), lit(1)))))
        inner.set("T2", add32(var("S2"), var("MJ")))
        inner.do(st.setv("H", st.getv("G")))
        inner.do(st.setv("G", st.getv("F")))
        inner.do(st.setv("F", st.getv("E")))
        inner.set("E", add32(var("D"), var("T1")))
        inner.do(st.setv("D", st.getv("C")))
        inner.do(st.setv("C", st.getv("B")))
        inner.do(st.setv("B", st.getv("A")))
        inner.set("A", add32(var("T1"), var("T2")))
        inner.change("R", lit(1))
        f.do(st.repeat(64, st.chain(*inner.out)))

        for i, name in enumerate("ABCDEFGH"):
            f.setitem("HS", lit(i + 1), add32(item("HS", lit(i + 1)), var(name)))
        return f.out

    # ---- sha256 ---------------------------------------------------------
    d, _ = st.def_proc("sha256", [])
    f = Fn(st)
    f.set("OUT_HEX", lit(""))
    for i in range(8):  # the chaining list is mutated in place: restore the IV
        f.setitem("HS", lit(i + 1), lit(IV[i]))
    # hash SRC, which the caller owns; BUF is the padded working copy
    f.do(st.clear("BUF"))
    f.do(st.setv("I", 1))
    copy = Fn(st)
    copy.addto("BUF", raw(st.item("SRC", st.getv("I"))))
    copy.change("I", lit(1))
    f.do(st.repeat(st.listlen("SRC"), st.chain(*copy.out)))
    f.do(st.setv("MSGLEN", st.listlen("SRC")))
    f.addto("BUF", lit(128))
    f.do(st.repeat_until(st.eq(st.mod(st.listlen("BUF"), 64), 56),
                         st.chain(st.addto("BUF", 0))))
    f.set("T1", op("mul", var("MSGLEN"), lit(8)))
    for shift in (56, 48, 40, 32, 24, 16, 8, 0):  # 64-bit big-endian length
        f.addto("BUF", op("mod", op("floor", op("div", var("T1"), lit(2 ** shift))),
                          lit(256)))
    f.set("NBLK", op("div", raw(st.listlen("BUF")), lit(64)))
    f.set("BLK", lit(0))
    loop = block_body() + [st.changev("BLK", 1)]
    f.do(st.repeat(st.getv("NBLK"), st.chain(*loop)))
    for w in range(8):
        for nib in range(7, -1, -1):
            f.set("OUT_HEX", op("join", var("OUT_HEX"),
                                item("HEXD", op("add",
                                                op("mod", op("floor", op("div", item("HS", lit(w + 1)),
                                                                         lit(2 ** (4 * nib)))), lit(16)),
                                                lit(1)))))
    st.chain(d, *f.out)
    st.script(d)

    # ---- solver mode ----------------------------------------------------
    # Input = challenge raw bytes || 4-byte nonce, exactly what Anubis's wasm
    # kernel hashes (it hex-decodes the challenge, then appends the nonce big
    # endian, or little endian when the challenge's last byte is >= 0x80).
    d, _ = st.def_proc("solve", [])
    f = Fn(st)
    inner = Fn(st)
    inner.do(st.clear("SRC"))
    inner.do(st.setv("I", 1))
    cp = Fn(st)
    cp.addto("SRC", raw(st.item("CHAL", st.getv("I"))))
    cp.change("I", lit(1))
    inner.do(st.repeat(st.listlen("CHAL"), st.chain(*cp.out)))
    be, le = Fn(st), Fn(st)
    for shift in (24, 16, 8, 0):
        be.addto("SRC", op("mod", op("floor", op("div", var("NONCE"), lit(2 ** shift))), lit(256)))
    for shift in (0, 8, 16, 24):
        le.addto("SRC", op("mod", op("floor", op("div", var("NONCE"), lit(2 ** shift))), lit(256)))
    inner.do(st.if_else(st.lt(st.item("CHAL", st.listlen("CHAL")), 128),
                        st.chain(*be.out), st.chain(*le.out)))
    inner.do(st.call_proc("sha256", []))
    # leading DIFF bits must be zero: read the first 32 bits as a number
    inner.do(st.setv("Z", 0))
    inner.do(st.setv("I", 1))
    chk = Fn(st)
    chk.set("Z", op("add", op("mul", var("Z"), lit(16)),
                    op("sub", raw(st.itemnum("HEXD", st.letter(st.getv("I"), st.getv("OUT_HEX")))),
                       lit(1))))
    chk.change("I", lit(1))
    inner.do(st.repeat(8, st.chain(*chk.out)))
    ok = st.eq(st.floor(st.div(st.getv("Z"),
                               st.item("POW2", st.sub(33, st.getv("DIFF"))))), 0)
    inner.do(st.if_else(ok,
                        st.setv("FOUND", 1),
                        st.changev("NONCE", 1)))
    # every 1024 tries: rate, progress and ETA into the mascot's speech bubble
    # (256 spams the renderer once TurboWarp is doing thousands per second)
    prog = Fn(st)
    # floor the elapsed time at 10 ms: a difficulty-0 solve finishes inside one
    # timer tick, and nonce/0 is Infinity in Scratch and a trap in wasm
    prog.set("ELAPSED", raw(st.timer()))
    prog.do(st.if_(st.lt(st.getv("ELAPSED"), 0.01), st.setv("ELAPSED", 0.01)))
    prog.set("HPS", op("div", op("round", op("mul",
                                                op("div", var("NONCE"), var("ELAPSED")),
                                                lit(100))), lit(100)))
    prog.set("ETA", op("div",
                       op("sub", item("POW2", op("add", var("DIFF"), lit(1))), var("NONCE")),
                       var("HPS")))
    prog.say(joined(
        op("round", var("HPS")), lit(" H/s  "),
        var("NONCE"), lit("/"), item("POW2", op("add", var("DIFF"), lit(1))),
        lit("  ETA "), op("round", var("ETA")), lit(" s")))
    inner.do(st.if_(st.and_(st.eq(st.mod(st.getv("NONCE"), 1024), 0),
                            st.gt(st.getv("NONCE"), 0)),
                    st.chain(*prog.out)))
    f.do(st.repeat_until(st.eq(st.getv("FOUND"), 1), st.chain(*inner.out)))
    f.set("ELAPSED", raw(st.timer()))
    f.do(st.if_(st.lt(st.getv("ELAPSED"), 0.01), st.setv("ELAPSED", 0.01)))
    f.set("HPS", op("div", op("round", op("mul",
                                          op("div", op("add", var("NONCE"), lit(1)), var("ELAPSED")),
                                          lit(100))), lit(100)))
    st.chain(d, *f.out)
    st.script(d)

    # ---- entry point: the mascot asks, then hashes ------------------------
    flag = st.when_flag()

    msg = Fn(st)
    msg.do(st.clear("SRC"))
    msg.do(st.setv("I", 1))
    cp = Fn(st)
    cp.addto("SRC", raw(st.item("MSG", st.getv("I"))))
    cp.change("I", lit(1))
    msg.do(st.repeat(st.listlen("MSG"), st.chain(*cp.out)))
    msg.do(st.reset_timer())
    msg.do(st.say("hashing your message in blocks..."))
    msg.do(st.call_proc("sha256", []))
    msg.say(joined(lit("SHA-256 = "), var("OUT_HEX")))
    msg.do(st.setv("DONE", 1))

    sol = Fn(st)
    # hex string -> raw bytes, two characters at a time
    sol.do(st.clear("CHAL"))
    sol.do(st.setv("I", 1))
    parse = Fn(st)
    # one nibble: lower-case table first, then upper-case (people paste both)
    # separate variables per nibble: reusing TMP2 here would make it both a
    # number and (later) the hash prefix, which no static type can survive
    for slot, offset in (("DIG0", 0), ("DIG1", 1)):
        idx = st.add(st.getv("I"), offset) if offset else st.getv("I")
        parse.do(st.setv(slot, st.itemnum("HEXD", st.letter(idx, st.getv("ANS")))))
        parse.do(st.if_(st.eq(st.getv(slot), 0),
                        st.setv(slot, st.itemnum("HEXDU", st.letter(idx, st.getv("ANS"))))))
    parse.addto("CHAL", op("add",
                           op("mul", op("sub", var("DIG0"), lit(1)), lit(16)),
                           op("sub", var("DIG1"), lit(1))))
    parse.change("I", lit(2))
    sol.do(st.repeat(st.div(st.length(st.getv("ANS")), 2), st.chain(*parse.out)))
    sol.do(st.ask("difficulty in bits? (Anubis usually 21)"))
    sol.do(st.setv("DIFF", st.answer()))
    sol.do(st.reset_timer())
    sol.say(joined(lit("ok, "), raw(st.listlen("CHAL")),
                   lit(" bytes of challenge at "), var("DIFF"),
                   lit(" bits. hashing...")))
    sol.do(st.call_proc("solve", []))
    # the first 16 hex characters of the digest, for the bubble
    sol.do(st.setv("TMP2", ""))
    sol.do(st.setv("I", 1))
    pref = Fn(st)
    pref.set("TMP2", op("join", var("TMP2"),
                        raw(st.letter(st.getv("I"), st.getv("OUT_HEX")))))
    pref.change("I", lit(1))
    sol.do(st.repeat(16, st.chain(*pref.out)))
    sol.say(joined(
        lit("solved! nonce "), var("NONCE"), lit(" in "),
        op("div", op("round", op("mul", var("ELAPSED"), lit(10))), lit(10)),
        lit(" s at "), op("round", var("HPS")), lit(" H/s"),
        lit(".  hash "), var("TMP2"), lit("...")))
    sol.do(st.setv("DONE", 1))

    st.chain(flag,
             st.setv("DONE", 0),
             st.setv("FOUND", 0),
             st.setv("NONCE", 0),
             st.setv("OUT_HEX", ""),
             st.setv("HPS", 0),
             st.say("I'm the anti-anti-AI mascot and I do the hashing in blocks."),
             st.ask("challenge hex? (or press Enter to just hash MSG)"),
             st.setv("ANS", st.answer()),
             st.if_else(st.eq(st.length(st.getv("ANS")), 0),
                        st.chain(*msg.out),
                        st.chain(*sol.out)))
    st.script(flag)

    out = out_path or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "build", "sha256.sb3")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    size = p.save(out)
    print("wrote %s" % out)
    print("  limb: %d bits, tables: %d entries, blocks: %d, project.json: %.1f KiB"
          % (limb, entries, sum(len(t.blocks) for t in p.targets), size / 1024.0))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limb", type=int, default=4, choices=(4, 8),
                    help="table lookup width in bits (4 -> 256 entries, 8 -> 65536)")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    gen(limb=a.limb, out_path=a.out)
