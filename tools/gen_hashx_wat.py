#!/usr/bin/env python3
"""gen_hashx_wat.py — compile a HashX program into straight-line WAT ("the JIT").

The HashX verifier is a 512-instruction VM over eight 64-bit registers. An
interpreter pays a dispatch per instruction; a HashX program is fixed for a whole
challenge, so the interpreter is avoidable entirely — that is what this generator
does, and it is the same idea that gave the 19.9x CUDA speedup (see SPEED.md).

    python3 tools/gen_hashx_wat.py                         # write wasm/hashx_jit.wat
    python3 tools/gen_hashx_wat.py --program beyond/vectors/hx_vectors.hex --case 0

Output exports:

    hash(nonce: i64) -> i64      leading zero bits of the digest; digest at memory 0
    solve(base: i64, difficulty: i64, count: i64) -> i64
                                 scans `count` nonces, returns the hit or -1
    digest(nonce: i64) -> i64    same as hash (alias, reads better in a demo)
    keys / ninstr                the program's parameters, for the harness

Control flow: the program has 16 BRANCH instructions but at most one is ever
taken (the `be` guard clears itself), so the generator nests one `loop` per
branch target. A branch becomes `br $L<target>`, which restarts that loop — the
straight-line equivalent of the backward goto the C interpreter performs.

Why WAT and not Rust/C: the point is to see what a *maximally dumb* backend
achieves when it does not interpret. Hand-emitted WAT has no optimiser behind it.
"""
from __future__ import annotations

import argparse
from pathlib import Path

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

OP_NAMES = {
    0: "UMULH_R", 1: "SMULH_R", 2: "MUL_R", 3: "SUB_R", 4: "XOR_R",
    5: "ADD_RS", 6: "ROR_C", 7: "ADD_C", 8: "XOR_C", 9: "TARGET", 10: "BRANCH",
}

PROGRAMS = {
    # case 0 of beyond/vectors/hx_vectors.hex: the same challenge the hardware
    # testbenches and the CUDA JIT use
    "vectors": {
        "challenge": "6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d",
        "nonce": 0,
    },
}


def sext32(x: int) -> int:
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def i64(v: int) -> str:
    return f"(i64.const {v - (1 << 64) if v & (1 << 63) else v})"


def load_program(path: Path, case: int) -> tuple[list[int], int, list[list[int]], list[int]]:
    """Return (keys, nonce, 512 x [op,dst,src,imm], expected[4]) from a vector file."""
    w = [int(line, 16) for line in path.read_text().split()]
    base = case * 2058
    keys = w[base + 0:base + 4]
    ninstr = w[base + 4]
    nonce = w[base + 5]
    prog = [w[base + 6 + 4 * k: base + 6 + 4 * k + 4] for k in range(512)]
    expected = w[base + 2054:base + 2058]
    return keys, nonce, prog[:ninstr], expected


class Wat:
    """Emits the module. Locals are fixed by name; every op is emitted in place."""

    def __init__(self, keys: list[int], prog: list[list[int]], expected: list[int]):
        self.keys = keys
        self.prog = prog
        self.expected = expected
        self.body: list[str] = []
        self.depth = 0

    # -- helpers ------------------------------------------------------
    def emit(self, line: str) -> None:
        self.body.append("  " * (2 + self.depth) + line)

    def open_loop(self, label: str) -> None:
        self.emit(f"(loop ${label}")
        self.depth += 1

    def close_loop(self) -> None:
        self.depth -= 1
        self.emit(")")

    def umulhi(self, x: str, y: str) -> None:
        """hi 64 bits of x*y, into $hi. Clobbers $t0..$t3, $lo."""
        e = self.emit
        e(f";; $hi = umulhi({x}, {y})")
        e(f"(local.set $t0 (i64.mul (i64.and (local.get {x}) {i64(M32)}) "
          f"(i64.and (local.get {y}) {i64(M32)})))")
        e(f"(local.set $t1 (i64.mul (i64.and (local.get {x}) {i64(M32)}) "
          f"(i64.shr_u (local.get {y}) (i64.const 32))))")
        e(f"(local.set $t2 (i64.mul (i64.shr_u (local.get {x}) (i64.const 32)) "
          f"(i64.and (local.get {y}) {i64(M32)})))")
        e(f"(local.set $t3 (i64.mul (i64.shr_u (local.get {x}) (i64.const 32)) "
          f"(i64.shr_u (local.get {y}) (i64.const 32))))")
        e("(local.set $lo (i64.add (i64.shr_u (local.get $t0) (i64.const 32)) "
          "(i64.add (i64.and (local.get $t1) (i64.const 4294967295)) "
          "(i64.and (local.get $t2) (i64.const 4294967295)))))")
        e("(local.set $hi (i64.add (local.get $t3) "
          "(i64.add (i64.shr_u (local.get $t1) (i64.const 32)) "
          "(i64.add (i64.shr_u (local.get $t2) (i64.const 32)) "
          "(i64.shr_u (local.get $lo) (i64.const 32))))))")

    def smulhi(self, x: str, y: str) -> None:
        """hi 64 bits of the signed product, into $hi. Clobbers $t0..$t3, $lo."""
        self.umulhi(x, y)
        e = self.emit
        e(f"(local.set $hi (i64.sub (local.get $hi) "
          f"(select (local.get {y}) (i64.const 0) (i64.lt_s (local.get {x}) (i64.const 0)))))")
        e(f"(local.set $hi (i64.sub (local.get $hi) "
          f"(select (local.get {x}) (i64.const 0) (i64.lt_s (local.get {y}) (i64.const 0)))))")

    def sipround(self, a: str, b: str, c: str, d: str) -> None:
        e = self.emit
        e(f"(local.set {a} (i64.add (local.get {a}) (local.get {b})))")
        e(f"(local.set {c} (i64.add (local.get {c}) (local.get {d})))")
        e(f"(local.set {b} (i64.rotl (local.get {b}) (i64.const 13)))")
        e(f"(local.set {d} (i64.rotl (local.get {d}) (i64.const 16)))")
        e(f"(local.set {b} (i64.xor (local.get {b}) (local.get {a})))")
        e(f"(local.set {d} (i64.xor (local.get {d}) (local.get {c})))")
        e(f"(local.set {a} (i64.rotl (local.get {a}) (i64.const 32)))")
        e(f"(local.set {c} (i64.add (local.get {c}) (local.get {b})))")
        e(f"(local.set {a} (i64.add (local.get {a}) (local.get {d})))")
        e(f"(local.set {b} (i64.rotl (local.get {b}) (i64.const 17)))")
        e(f"(local.set {d} (i64.rotl (local.get {d}) (i64.const 21)))")
        e(f"(local.set {b} (i64.xor (local.get {b}) (local.get {c})))")
        e(f"(local.set {d} (i64.xor (local.get {d}) (local.get {a})))")
        e(f"(local.set {c} (i64.rotl (local.get {c}) (i64.const 32)))")

    # -- structure ----------------------------------------------------
    def prf(self) -> None:
        """Counter-mode SipHash-2-4 producing r0..r7, exactly as the C engine does."""
        k = self.keys
        e = self.emit
        e(";; ---- PRF: SipHash-2-4 in counter mode ----")
        e(f"(local.set $v0 {i64(k[0])})")
        e(f"(local.set $v1 {i64(k[1])})")
        e(f"(local.set $v2 {i64(k[2])})")
        e(f"(local.set $v3 {i64(k[3])})")
        e("(local.set $v1 (i64.xor (local.get $v1) (i64.const 238)))")
        e("(local.set $v3 (i64.xor (local.get $v3) (local.get $nonce)))")
        for _ in range(2):
            self.sipround("$v0", "$v1", "$v2", "$v3")
        e("(local.set $v0 (i64.xor (local.get $v0) (local.get $nonce)))")
        e("(local.set $v2 (i64.xor (local.get $v2) (i64.const 238)))")
        for _ in range(4):
            self.sipround("$v0", "$v1", "$v2", "$v3")
        for i in range(4):
            e(f"(local.set $r{i} (local.get $v{i}))")
        e("(local.set $v1 (i64.xor (local.get $v1) (i64.const 221)))")
        for _ in range(4):
            self.sipround("$v0", "$v1", "$v2", "$v3")
        for i in range(4):
            e(f"(local.set $r{4 + i} (local.get $v{i}))")

    def vm(self) -> None:
        """The 512 instructions, unrolled, with one nested loop per branch target."""
        e = self.emit
        target_of = {}          # branch index -> target instruction index
        last_target = None
        for i, (op, _dst, _src, _imm) in enumerate(self.prog):
            if op == 9:
                last_target = i
            elif op == 10:
                target_of[i] = (last_target + 1) if last_target is not None else 0

        # A loop head is needed at every branch target so `br` can jump back to it.
        heads = sorted({t for t in target_of.values() if t < len(self.prog)})
        e(";; ---- the program, compiled to straight line ----")
        open_heads = set()
        for i, (op, dst, src, imm) in enumerate(self.prog):
            if i in heads:
                self.open_loop(f"L{i}")
                open_heads.add(i)
            d, s = dst & 7, src & 7

            if op == 9:
                continue                      # TARGET records a position only
            if op == 10:
                tgt = target_of[i]
                e(f";; BRANCH {i}: be && (result & 0x{imm & M32:08x}) == 0 -> {tgt}")
                e(f"(if (i32.and (local.get $be) "
                  f"(i64.eq (i64.and (local.get $result) {i64(imm & M32)}) {i64(0)}))")
                self.depth += 1
                self.emit('(then')
                self.depth += 1
                self.emit("(local.set $be (i32.const 0))")
                if tgt in heads:
                    self.emit(f"(br $L{tgt})")
                else:
                    self.emit(f";; target {tgt} is the end of the program: fall through")
                self.depth -= 1
                self.emit(")")
                self.depth -= 1
                e(")")
                continue

            if op == 0:
                self.umulhi(f"$r{d}", f"$r{s}")
                e(f"(local.set $r{d} (local.get $hi))")
                e(f"(local.set $result (local.get $hi))")
            elif op == 1:
                self.smulhi(f"$r{d}", f"$r{s}")
                e(f"(local.set $r{d} (local.get $hi))")
                e(f"(local.set $result (local.get $hi))")
            elif op == 2:
                e(f"(local.set $r{d} (i64.mul (local.get $r{d}) (local.get $r{s})))")
            elif op == 3:
                e(f"(local.set $r{d} (i64.sub (local.get $r{d}) (local.get $r{s})))")
            elif op == 4:
                e(f"(local.set $r{d} (i64.xor (local.get $r{d}) (local.get $r{s})))")
            elif op == 5:
                e(f"(local.set $r{d} (i64.add (local.get $r{d}) "
                  f"(i64.shl (local.get $r{s}) (i64.const {imm & 63}))))")
            elif op == 6:
                e(f"(local.set $r{d} (i64.rotr (local.get $r{d}) (i64.const {imm & 63})))")
            elif op == 7:
                e(f"(local.set $r{d} (i64.add (local.get $r{d}) {i64(sext32(imm) & M64)}))")
            elif op == 8:
                e(f"(local.set $r{d} (i64.xor (local.get $r{d}) {i64(sext32(imm) & M64)}))")
            else:
                raise SystemExit(f"unknown opcode {op} at {i}")

        while open_heads:
            # close every loop opened above, innermost first
            self.close_loop()
            open_heads.pop()

    def finalize(self) -> None:
        """Add the keys back, one SipRound per half, xor the halves, store 32 bytes."""
        k = self.keys
        e = self.emit
        e(";; ---- finalisation ----")
        for reg, key in ((0, k[0]), (1, k[1]), (6, k[2]), (7, k[3])):
            e(f"(local.set $r{reg} (i64.add (local.get $r{reg}) {i64(key)}))")
        self.sipround("$r0", "$r1", "$r2", "$r3")
        self.sipround("$r4", "$r5", "$r6", "$r7")
        for i in range(4):
            e(f"(local.set $w{i} (i64.xor (local.get $r{i}) (local.get $r{4 + i})))")
        e(";; the digest is four little-endian 64-bit words, 32 bytes at address 0")
        for i in range(4):
            e(f"(i64.store offset={8 * i} (i32.const 0) (local.get $w{i}))")

    def lz_function(self) -> str:
        """Leading zero bits of the 32-byte digest, MSB-first within each byte."""
        return """  ;; leading zero bits of the digest at address 0, which is the hashx difficulty
  ;; unit: byte k is (w[k>>3] >> (8*(k&7))) & 0xff and its high bit is tested first
  (func $lz (result i64)
    (local $k i32) (local $bits i64) (local $byte i32)
    (local.set $k (i32.const 0))
    (local.set $bits (i64.const 0))
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $k) (i32.const 32)))
        (local.set $byte (i32.load8_u (local.get $k)))
        (if (i32.eqz (local.get $byte))
          (then (local.set $bits (i64.add (local.get $bits) (i64.const 8))))
          (else
            ;; i32.clz of a nonzero byte is 24..31; subtract 24 for the byte itself
            (local.set $bits (i64.add (local.get $bits)
              (i64.extend_i32_u (i32.sub (i32.clz (local.get $byte)) (i32.const 24)))))
            (br $done)))
        (local.set $k (i32.add (local.get $k) (i32.const 1)))
        (br $next)))
    (local.get $bits))
"""

    def build(self) -> str:
        e = self.emit
        self.emit("(module")
        self.depth = -1   # (module is at depth 0 for children
        self.depth = 0
        e('  (memory (export "memory") 1)')

        # ---- $hash: one full HashX hash ----
        e("  (func $hash (export \"hash\") (param $nonce i64) (result i64)")
        locals_ = "".join(f"    (local $r{i} i64)\n" for i in range(8))
        locals_ += "".join(f"    (local $w{i} i64)\n" for i in range(4))
        locals_ += "    (local $v0 i64) (local $v1 i64) (local $v2 i64) (local $v3 i64)\n"
        locals_ += "    (local $result i64) (local $hi i64) (local $lo i64)\n"
        locals_ += "    (local $t0 i64) (local $t1 i64) (local $t2 i64) (local $t3 i64)\n"
        locals_ += "    (local $be i32)\n"
        self.body.append(locals_.rstrip("\n"))
        e("    (local.set $be (i32.const 1))")
        self.prf()
        self.vm()
        self.finalize()
        e("    (call $lz))")
        self.body.append("")

        # ---- $solve: the scan loop, kept inside wasm ----
        e("  ;; scan `count` nonces from `base`; returns the hit or -1. difficulty 64")
        e("  ;; never hits, which is how the benchmark measures pure hashing.")
        e('  (func (export "solve") (param $base i64) (param $difficulty i64) (param $count i64) '
          "(result i64)")
        e("    (local $n i64) (local $end i64) (local $bits i64)")
        e("    (local.set $n (local.get $base))")
        e("    (local.set $end (i64.add (local.get $base) (local.get $count)))")
        e("    (block $miss")
        e("      (loop $scan")
        e("        (br_if $miss (i64.ge_s (local.get $n) (local.get $end)))")
        e("        (local.set $bits (call $hash (local.get $n)))")
        e("        (if (i64.ge_s (local.get $bits) (local.get $difficulty))")
        e("          (then (return (local.get $n))))")
        e("        (local.set $n (i64.add (local.get $n) (i64.const 1)))")
        e("        (br $scan)))")
        e("    (i64.const -1))")

        e("  ;; the program this module was compiled for")
        e(f'  (func (export "ninstr") (result i32) (i32.const {len(self.prog)}))')
        e(f'  (global (export "challenge_nonce") i64 {i64(0)})')
        self.depth = 0
        e(")")
        return "\n".join(self.body) + "\n"

    def lz_stub(self) -> str:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--program", default=None,
                    help="vector file (default: the built-in single-case program)")
    ap.add_argument("--case", type=int, default=0)
    ap.add_argument("--out", default="wasm/hashx_jit.wat")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    if args.program:
        keys, nonce, prog, expected = load_program(Path(args.program), args.case)
        challenge = ""
    else:
        vec = root / "beyond" / "vectors" / "hx_vectors.hex"
        if vec.exists():
            keys, nonce, prog, expected = load_program(vec, args.case)
        else:
            raise SystemExit("no vector file and no --program given")
        challenge = PROGRAMS["vectors"]["challenge"]

    w = Wat(keys, prog, expected)
    module = w.build()

    # $lz is defined after $hash refers to it; WAT resolves forward references, so
    # splice the function in before the closing parenthesis of the module.
    lz = Wat.lz_function(w)
    module = module.replace('  ;; the program this module was compiled for',
                            lz + '  ;; the program this module was compiled for')

    header = (f";; HashX compiled to WAT by tools/gen_hashx_wat.py -- {len(prog)} instructions,\n"
              f";; challenge {challenge or '(from --program)'}, nonce {nonce}, "
              f"keys {', '.join(hex(k) for k in keys)}\n")
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(header + module)
    print(f"wrote {out} ({len(module.splitlines())} lines, {len(prog)} instructions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
