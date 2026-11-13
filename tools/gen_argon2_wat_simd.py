#!/usr/bin/env python3
"""gen_argon2_wat_simd.py — Argon2id fill_block with explicit wasm SIMD (v128).

Two 64-bit words per vector register: q0=[w0,w1], q1=[w2,w3], ... q7=[w14,w15].
The scalar round's G(i, i+4, i+8, i+12) for i=0,1 is one vector G over
(q0,q2,q4,q6), and i=2,3 is (q1,q3,q5,q7) — exact 2x with no shuffling. The
diagonal G's cross lanes and need shuffles, derived below.

Why WAT and not Rust: Rust's stable `core::arch::wasm32` exposes only the
*signed* `i64x2_extmul_low_i32x4`, and fBlaMka needs the **unsigned** 32x32->64
multiply. The wasm opcode `i64x2.extmul_low_i32x4_u` exists; the binding does not.
In WAT it is one instruction.

    python3 tools/gen_argon2_wat_simd.py --out wasm/argon2_fill_simd.wat
"""
from __future__ import annotations

import argparse
from pathlib import Path

TMP, R, ARENA = 0, 1024, 4096

# --- byte indices for i8x16.shuffle (0-15 = a, 16-31 = b) ---
LO32 = (0, 1, 2, 3, 8, 9, 10, 11, 0, 1, 2, 3, 8, 9, 10, 11)      # low u32 of each u64 lane
R32 = (4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11)     # rotr 32
R24 = (3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10)     # rotr 24
R16 = (2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9)     # rotr 16
HI_LO = (8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)   # a.hi ++ b.lo
LO_KEEP = (0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23)       # keep a.lo, take b.lo
HI_KEEP = (8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31) # a.hi ++ b.hi


class Gen:
    def __init__(self) -> None:
        self.out: list[str] = []

    def e(self, line: str) -> None:
        self.out.append("    " + line)

    def shuffle(self, dst: str, a: str, b: str, idx: tuple[int, ...]) -> None:
        self.e(f"(local.set ${dst} (i8x16.shuffle {' '.join(map(str, idx))} "
               f"(local.get ${a}) (local.get ${b})))")

    def blamka(self, dst: str, x: str, y: str) -> None:
        """fBlaMka: x + y + 2*(x&0xffffffff)*(y&0xffffffff), unsigned 32x32->64."""
        self.e(f"(local.set $t0 (i8x16.shuffle {' '.join(map(str, LO32))} "
               f"(local.get ${x}) (local.get ${x})))")
        self.e(f"(local.set $t1 (i8x16.shuffle {' '.join(map(str, LO32))} "
               f"(local.get ${y}) (local.get ${y})))")
        self.e("(local.set $t2 (i64x2.extmul_low_i32x4_u (local.get $t0) (local.get $t1)))")
        self.e(f"(local.set ${dst} (i64x2.add (i64x2.add (local.get ${x}) (local.get ${y})) "
               f"(i64x2.add (local.get $t2) (local.get $t2))))")

    def rotr(self, dst: str, x: str, idx: tuple[int, ...] | None) -> None:
        if idx is not None:
            self.e(f"(local.set ${dst} (i8x16.shuffle {' '.join(map(str, idx))} "
                   f"(local.get ${x}) (local.get ${x})))")
        else:   # 63 == rotl 1
            self.e(f"(local.set ${dst} (v128.xor (i64x2.shl (local.get ${x}) (i32.const 1)) "
                   f"(i64x2.shr_u (local.get ${x}) (i32.const 63))))")

    def g(self, a: str, b: str, c: str, d: str) -> None:
        self.blamka(a, a, b)
        self.e(f"(local.set ${d} (v128.xor (local.get ${d}) (local.get ${a})))")
        self.rotr(d, d, R32)
        self.blamka(c, c, d)
        self.e(f"(local.set ${b} (v128.xor (local.get ${b}) (local.get ${c})))")
        self.rotr(b, b, R24)
        self.blamka(a, a, b)
        self.e(f"(local.set ${d} (v128.xor (local.get ${d}) (local.get ${a})))")
        self.rotr(d, d, R16)
        self.blamka(c, c, d)
        self.e(f"(local.set ${b} (v128.xor (local.get ${b}) (local.get ${c})))")
        self.rotr(b, b, None)

    def round16(self, label: str) -> None:
        """One BLAKE2 round over the 16 words held in q0..q7."""
        self.e(f";; {label}: columns G(i,i+4,i+8,i+12) for i=0,1 / 2,3")
        self.g("q0", "q2", "q4", "q6")
        self.g("q1", "q3", "q5", "q7")

        self.e(";; diagonals, pair 1: G(0,5,10,15) + G(1,6,11,12)")
        self.e(";;   A=q0  B=[w5,w6]  C=q5  D=[w15,w12]")
        self.shuffle("b0", "q2", "q3", HI_LO)
        self.shuffle("d0", "q7", "q6", HI_LO)
        self.g("q0", "b0", "q5", "d0")
        self.shuffle("t2", "q2", "b0", LO_KEEP); self.e("(local.set $q2 (local.get $t2))")
        self.shuffle("t2", "b0", "q3", HI_KEEP); self.e("(local.set $q3 (local.get $t2))")
        self.shuffle("t2", "q7", "d0", LO_KEEP); self.e("(local.set $q7 (local.get $t2))")
        self.shuffle("t2", "d0", "q6", HI_KEEP); self.e("(local.set $q6 (local.get $t2))")

        self.e(";; diagonals, pair 2: G(2,7,8,13) + G(3,4,9,14)")
        self.e(";;   A=q1  B=[w7,w4]  C=q4  D=[w13,w14]")
        self.shuffle("b0", "q3", "q2", HI_LO)
        self.shuffle("d0", "q6", "q7", HI_LO)
        self.g("q1", "b0", "q4", "d0")
        self.shuffle("t2", "q3", "b0", LO_KEEP); self.e("(local.set $q3 (local.get $t2))")
        self.shuffle("t2", "b0", "q2", HI_KEEP); self.e("(local.set $q2 (local.get $t2))")
        self.shuffle("t2", "q6", "d0", LO_KEEP); self.e("(local.set $q6 (local.get $t2))")
        self.shuffle("t2", "d0", "q7", HI_KEEP); self.e("(local.set $q7 (local.get $t2))")

    def load16(self, addr: str) -> None:
        for j in range(8):
            self.e(f"(local.set $q{j} (v128.load offset={16 * j} ({addr})))")

    def store16(self, addr: str) -> None:
        for j in range(8):
            self.e(f"(v128.store offset={16 * j} ({addr}) (local.get $q{j}))")

    def build(self) -> str:
        e = self.e
        self.out.append("(module")
        e('(memory (export "memory") 320)')
        e(";; scratch: block_tmp at 0, blockR at 1024; caller blocks at 2048+")
        e('(func (export "fill_block") (param $dst i32) (param $prev i32) (param $ref i32) (param $xor i32)')
        e("  (local $i i32) (local $base i32)")
        e("  (local $q0 v128) (local $q1 v128) (local $q2 v128) (local $q3 v128)")
        e("  (local $q4 v128) (local $q5 v128) (local $q6 v128) (local $q7 v128)")
        e("  (local $b0 v128) (local $d0 v128)")
        e("  (local $t0 v128) (local $t1 v128) (local $t2 v128)")
        e("")
        e(";; ---- blockR = ref ^ prev ; block_tmp = blockR ^ (xor ? dst : 0), 2 words at a time ----")
        e("(local.set $i (i32.const 0))")
        e("(block $copy_done (loop $copy")
        e("  (br_if $copy_done (i32.ge_u (local.get $i) (i32.const 1024)))")
        e("  (v128.store (i32.add (i32.const 1024) (local.get $i))")
        e("    (v128.xor (v128.load (i32.add (local.get $ref) (local.get $i)))")
        e("              (v128.load (i32.add (local.get $prev) (local.get $i)))))")
        e("  (if (local.get $xor) (then")
        e("    (v128.store (local.get $i)")
        e("      (v128.xor (v128.load (i32.add (i32.const 1024) (local.get $i)))")
        e("                (v128.load (i32.add (local.get $dst) (local.get $i))))))")
        e("   (else")
        e("    (v128.store (local.get $i) (v128.load (i32.add (i32.const 1024) (local.get $i))))))")
        e("  (local.set $i (i32.add (local.get $i) (i32.const 16)))")
        e("  (br $copy)))")
        e("")
        e(";; ---- 8 column rounds and 8 row rounds ----")
        e("(local.set $base (i32.const 1024))")
        for grp in range(8):
            e(f";; column round {grp}: words {16 * grp}..{16 * grp + 15}")
            self.load16("i32.add (local.get $base) (i32.const {})".format(16 * grp * 8))
            self.round16(f"column {grp}")
            self.store16("i32.add (local.get $base) (i32.const {})".format(16 * grp * 8))
        e("")
        for grp in range(8):
            e(f";; row round {grp}: words {2 * grp},{2 * grp + 1},{2 * grp + 16},...")
            # gather the 8 pairs of this row into q0..q7: pair j is (2grp+16j, +1)
            for j in range(8):
                e(f"(local.set $q{j} (v128.load offset={(2 * grp + 16 * j) * 8} (local.get $base)))")
            self.round16(f"row {grp}")
            for j in range(8):
                e(f"(v128.store offset={(2 * grp + 16 * j) * 8} (local.get $base) (local.get $q{j}))")
        e("")
        e(";; ---- dst = block_tmp ^ blockR ----")
        e("(local.set $i (i32.const 0))")
        e("(block $out_done (loop $out")
        e("  (br_if $out_done (i32.ge_u (local.get $i) (i32.const 1024)))")
        e("  (v128.store (i32.add (local.get $dst) (local.get $i))")
        e("    (v128.xor (v128.load (local.get $i))")
        e("              (v128.load (i32.add (i32.const 1024) (local.get $i)))))")
        e("  (local.set $i (i32.add (local.get $i) (i32.const 16)))")
        e("  (br $out)))")
        e(")")
        e("")
        e('(func (export "blocks") (result i32) (i32.const 128))')
        self.out.append(")")
        return "\n".join(self.out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="wasm/argon2_fill_simd.wat")
    args = ap.parse_args()
    module = Gen().build()
    root = Path(__file__).resolve().parent.parent
    out = root / args.out
    header = (";; Argon2id fill_block with explicit v128 SIMD, generated by\n"
              ";; tools/gen_argon2_wat_simd.py. Two u64 per register; the diagonal G's\n"
              ";; need shuffles, the column G's pair exactly. Uses i64x2.extmul_low_i32x4_u,\n"
              ";; which Rust's stable core::arch::wasm32 does not expose.\n")
    out.write_text(header + module)
    print(f"wrote {out} ({len(module.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
