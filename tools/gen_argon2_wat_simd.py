#!/usr/bin/env python3
"""gen_argon2_wat_simd.py — Argon2id fill_block with explicit wasm v128 SIMD.

The block is held as eight v128 registers, two u64 words per register, so one
vector G does the work of two scalar G's. What a v128 costs here is *shuffles*:
`fBlaMka` needs the unsigned 32x32->64 product of the low halves of both lanes,
and `i64x2.extmul_low_i32x4_u` multiplies i32 lanes 0 and 1 of each operand --
in the natural u64 layout that is lo*lo and hi*hi of the *same* word, not the
low halves of both words. So the two low halves have to be gathered into i32
lanes 0 and 1 first (one `i8x16.shuffle` per operand), and V8 lowers the extmul
itself as two more `vpunpckldq` plus `vpmuludq`. Four shuffle-port uops per
fBlaMka; x86 has one shuffle port. That, not the arithmetic, is what decides
this comparison (see the module docstring in `wasm/bench-fill-inmodule.mjs`
for the measured breakdown).

Layout and round structure follow the vendored reference's SSSE3 path
(`third_party/argon2/blake2/blamka-round-opt.h`):

  * column G's pair exactly: G(0,4,8,12)+G(1,5,9,13) is one vector G.
  * the diagonal G's need B and D rotated by one lane. `DIAGONALIZE` is four
    shuffles (C is just the other register, free), `UNDIAGONALIZE` four more;
    the previous version of this generator materialised both diagonals in
    scratch registers and paid twelve.
  * the two 64-bit G halves are emitted interleaved (G1 lane pair 0, G1 lane
    pair 1, G2 lane pair 0, G2 lane pair 1) so two independent chains are in
    flight, as the reference C does.

The `with_xor` copy and the final XOR are unrolled to 64 v128 steps: a loop
there costs ~0.15 us/block, which is more than the round restructuring buys.

    python3 tools/gen_argon2_wat_simd.py --out wasm/argon2_fill_simd.wat

Exports (same ABI as wasm/argon2_fill.wasm):

    fill_block(dst, prev, ref, with_xor)   one 1 KiB block, addresses in bytes
    blocks                                 128

Scratch lives at 0 (block_tmp) and 1024 (blockR), so caller blocks must start
at 2048 or above. `--variant` emits the other formulations this one was chosen
over, and `--bench` appends an in-module `bench` loop; both exist so
`wasm/bench-fill-inmodule.mjs` can compare them on identical work and check
every one against `wasm/fill_vectors.txt` (vectors from the vendored C
reference itself).
"""

from __future__ import annotations

import argparse
from pathlib import Path

M32 = 0xFFFFFFFF
TMP = 0
R = 1024
ARENA = 4096

# i8x16.shuffle byte indices. 0-15 select from the first operand, 16-31 the
# second. LO32 gathers the low dword of each u64 lane into i32 lanes 0 and 1,
# which is the operand layout i64x2.extmul_low_i32x4_u needs.
LO32 = (0, 1, 2, 3, 8, 9, 10, 11, 0, 1, 2, 3, 8, 9, 10, 11)
R32 = (4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11)
R24 = (3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10)
R16 = (2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9)
HI_LO = (8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)
LO_KEEP = (0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23)
HI_KEEP = (8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31)


def shuf(idx: tuple[int, ...]) -> str:
    return "i8x16.shuffle " + " ".join(map(str, idx))


class Gen:
    def __init__(self) -> None:
        self.out: list[str] = []

    def e(self, line: str) -> None:
        self.out.append("    " + line)

    # -- fBlaMka ---------------------------------------------------------
    def blamka(self, x: str, y: str) -> None:
        """fBlaMka(x,y) = x + y + 2*(x&0xffffffff)*(y&0xffffffff), unsigned 32x32->64."""
        self.e(f"(local.set $t0 ({shuf(LO32)} (local.get ${x}) (local.get ${x})))")
        self.e(f"(local.set $t1 ({shuf(LO32)} (local.get ${y}) (local.get ${y})))")
        self.e("(local.set $t0 (i64x2.extmul_low_i32x4_u (local.get $t0) (local.get $t1)))")
        self.e(
            f"(local.set ${x} (i64x2.add (i64x2.add (local.get ${x}) (local.get ${y})) "
            f"(i64x2.add (local.get $t0) (local.get $t0))))"
        )

    def rot(self, x: str, n: int, rot_alu: bool) -> None:
        """rotr64 in place. 32/24/16 are byte shuffles; 63 is shl1|xor.

        The 24/16 byte rotations can also be three shifts and an or (no
        shuffle port). It measures slower on V8, so the shuffle form is the
        default; `--variant simd_rot_alu` exists to show the number."""
        if n in (24, 16) and rot_alu:
            self.e(
                f"(local.set ${x} (v128.or (i64x2.shr_u (local.get ${x}) (i32.const {n})) "
                f"(i64x2.shl (local.get ${x}) (i32.const {64 - n}))))"
            )
        elif n in (24, 16):
            self.e(
                f"(local.set ${x} ({shuf(R24 if n == 24 else R16)} "
                f"(local.get ${x}) (local.get ${x})))"
            )
        elif n == 32:
            self.e(f"(local.set ${x} ({shuf(R32)} (local.get ${x}) (local.get ${x})))")
        else:
            self.e(
                f"(local.set ${x} (v128.xor (i64x2.shl (local.get ${x}) (i32.const 1)) "
                f"(i64x2.shr_u (local.get ${x}) (i32.const 63))))"
            )

    # -- G, split in halves so the two lane pairs interleave ---------------
    def g1(self, a: str, b: str, c: str, d: str, rot_alu: bool) -> None:
        self.blamka(a, b)
        self.e(f"(local.set ${d} (v128.xor (local.get ${d}) (local.get ${a})))")
        self.rot(d, 32, rot_alu)
        self.blamka(c, d)
        self.e(f"(local.set ${b} (v128.xor (local.get ${b}) (local.get ${c})))")
        self.rot(b, 24, rot_alu)

    def g2(self, a: str, b: str, c: str, d: str, rot_alu: bool) -> None:
        self.blamka(a, b)
        self.e(f"(local.set ${d} (v128.xor (local.get ${d}) (local.get ${a})))")
        self.rot(d, 16, rot_alu)
        self.blamka(c, d)
        self.e(f"(local.set ${b} (v128.xor (local.get ${b}) (local.get ${c})))")
        self.rot(b, 63, rot_alu)

    def g(self, a: str, b: str, c: str, d: str, rot_alu: bool) -> None:
        self.g1(a, b, c, d, rot_alu)
        self.g2(a, b, c, d, rot_alu)

    def round_pair(self, rot_alu: bool, interleave: bool) -> None:
        """One BLAKE2 round over the 16 words in q0..q7 (two u64 per register).

        q0=[0,1] q1=[2,3] q2=[4,5] q3=[6,7] q4=[8,9] q5=[10,11] q6=[12,13]
        q7=[14,15]. Column G's: (q0,q2,q4,q6) and (q1,q3,q5,q7)."""
        if interleave:
            self.g1("q0", "q2", "q4", "q6", rot_alu)
            self.g1("q1", "q3", "q5", "q7", rot_alu)
            self.g2("q0", "q2", "q4", "q6", rot_alu)
            self.g2("q1", "q3", "q5", "q7", rot_alu)
        else:
            self.g("q0", "q2", "q4", "q6", rot_alu)
            self.g("q1", "q3", "q5", "q7", rot_alu)
        # diagonalise: B and D rotate by one lane, C is the other register.
        self.e(f"(local.set $b0 ({shuf(HI_LO)} (local.get $q2) (local.get $q3)))")
        self.e(f"(local.set $b1 ({shuf(HI_LO)} (local.get $q3) (local.get $q2)))")
        self.e(f"(local.set $d0 ({shuf(HI_LO)} (local.get $q7) (local.get $q6)))")
        self.e(f"(local.set $d1 ({shuf(HI_LO)} (local.get $q6) (local.get $q7)))")
        # G(0,5,10,15)+G(1,6,11,12) in q0/b0/q5/d0; G(2,7,8,13)+G(3,4,9,14)
        # in q1/b1/q4/d1.
        if interleave:
            self.g1("q0", "b0", "q5", "d0", rot_alu)
            self.g1("q1", "b1", "q4", "d1", rot_alu)
            self.g2("q0", "b0", "q5", "d0", rot_alu)
            self.g2("q1", "b1", "q4", "d1", rot_alu)
        else:
            self.g("q0", "b0", "q5", "d0", rot_alu)
            self.g("q1", "b1", "q4", "d1", rot_alu)
        # undiagonalise
        self.e(f"(local.set $q2 ({shuf(HI_LO)} (local.get $b1) (local.get $b0)))")
        self.e(f"(local.set $q3 ({shuf(HI_LO)} (local.get $b0) (local.get $b1)))")
        self.e(f"(local.set $q6 ({shuf(HI_LO)} (local.get $d0) (local.get $d1)))")
        self.e(f"(local.set $q7 ({shuf(HI_LO)} (local.get $d1) (local.get $d0)))")

    def round_legacy(self, rot_alu: bool) -> None:
        """The previous generator's round: twelve diagonal shuffles.

        Kept so the benchmark can show what the reference structure bought."""
        self.g("q0", "q2", "q4", "q6", rot_alu)
        self.g("q1", "q3", "q5", "q7", rot_alu)
        self.e(f"(local.set $b0 ({shuf(HI_LO)} (local.get $q2) (local.get $q3)))")
        self.e(f"(local.set $d0 ({shuf(HI_LO)} (local.get $q7) (local.get $q6)))")
        self.g("q0", "b0", "q5", "d0", rot_alu)
        self.e(f"(local.set $t0 ({shuf(LO_KEEP)} (local.get $q2) (local.get $b0)))")
        self.e("(local.set $q2 (local.get $t0))")
        self.e(f"(local.set $t0 ({shuf(HI_KEEP)} (local.get $b0) (local.get $q3)))")
        self.e("(local.set $q3 (local.get $t0))")
        self.e(f"(local.set $t0 ({shuf(LO_KEEP)} (local.get $q7) (local.get $d0)))")
        self.e("(local.set $q7 (local.get $t0))")
        self.e(f"(local.set $t0 ({shuf(HI_KEEP)} (local.get $d0) (local.get $q6)))")
        self.e("(local.set $q6 (local.get $t0))")
        self.e(f"(local.set $b0 ({shuf(HI_LO)} (local.get $q3) (local.get $q2)))")
        self.e(f"(local.set $d0 ({shuf(HI_LO)} (local.get $q6) (local.get $q7)))")
        self.g("q1", "b0", "q4", "d0", rot_alu)
        self.e(f"(local.set $t0 ({shuf(LO_KEEP)} (local.get $q3) (local.get $b0)))")
        self.e("(local.set $q3 (local.get $t0))")
        self.e(f"(local.set $t0 ({shuf(HI_KEEP)} (local.get $b0) (local.get $q2)))")
        self.e("(local.set $q2 (local.get $t0))")
        self.e(f"(local.set $t0 ({shuf(LO_KEEP)} (local.get $q6) (local.get $d0)))")
        self.e("(local.set $q6 (local.get $t0))")
        self.e(f"(local.set $t0 ({shuf(HI_KEEP)} (local.get $d0) (local.get $q7)))")
        self.e("(local.set $q7 (local.get $t0))")

    # -- the copy and the final XOR ---------------------------------------
    def copy_loop(self) -> None:
        self.e(";; ---- blockR = ref ^ prev ; block_tmp = blockR ^ (with_xor ? dst : 0) ----")
        self.e("(local.set $i (i32.const 0))")
        self.e("(block $cd (loop $cl")
        self.e("  (br_if $cd (i32.ge_u (local.get $i) (i32.const 1024)))")
        self.e("  (local.set $t0 (v128.xor (v128.load (i32.add (local.get $ref) (local.get $i)))")
        self.e(
            "                            (v128.load (i32.add (local.get $prev) (local.get $i)))))"
        )
        self.e("  (v128.store (i32.add (i32.const 1024) (local.get $i)) (local.get $t0))")
        self.e("  (if (local.get $xor) (then")
        self.e("    (v128.store (local.get $i)")
        self.e(
            "      (v128.xor (local.get $t0) (v128.load (i32.add (local.get $dst) (local.get $i))))))"
        )
        self.e("   (else (v128.store (local.get $i) (local.get $t0))))")
        self.e("  (local.set $i (i32.add (local.get $i) (i32.const 16)))")
        self.e("  (br $cl)))")

    def copy_unrolled(self) -> None:
        self.e(";; ---- blockR = ref ^ prev ; block_tmp = blockR ^ (with_xor ? dst : 0) ----")
        self.e(";; the branch is hoisted out of the loop and the 64 v128 steps are straight-line:")
        self.e(";; a 64-iteration loop here measured 0.15 us/block slower than this.")
        self.e("(if (local.get $xor) (then")
        for k in range(64):
            o = 16 * k
            self.e(
                f"  (local.set $t0 (v128.xor (v128.load offset={o} (local.get $ref)) "
                f"(v128.load offset={o} (local.get $prev))))"
            )
            self.e(f"  (v128.store offset={o} (i32.const {R}) (local.get $t0))")
            self.e(
                f"  (local.set $t0 (v128.xor (local.get $t0) (v128.load offset={o} (local.get $dst))))"
            )
            self.e(f"  (v128.store offset={o} (i32.const {TMP}) (local.get $t0))")
        self.e(") (else")
        for k in range(64):
            o = 16 * k
            self.e(
                f"  (local.set $t0 (v128.xor (v128.load offset={o} (local.get $ref)) "
                f"(v128.load offset={o} (local.get $prev))))"
            )
            self.e(f"  (v128.store offset={o} (i32.const {R}) (local.get $t0))")
            self.e(f"  (v128.store offset={o} (i32.const {TMP}) (local.get $t0))")
        self.e("))")

    def out_loop(self) -> None:
        self.e(";; ---- dst = block_tmp ^ blockR ----")
        self.e("(local.set $i (i32.const 0))")
        self.e("(block $od (loop $ol")
        self.e("  (br_if $od (i32.ge_u (local.get $i) (i32.const 1024)))")
        self.e("  (v128.store (i32.add (local.get $dst) (local.get $i))")
        self.e("    (v128.xor (v128.load (i32.add (i32.const 0) (local.get $i)))")
        self.e("              (v128.load (i32.add (i32.const 1024) (local.get $i)))))")
        self.e("  (local.set $i (i32.add (local.get $i) (i32.const 16)))")
        self.e("  (br $ol)))")

    def out_unrolled(self) -> None:
        self.e(";; ---- dst = block_tmp ^ blockR ----")
        for k in range(64):
            o = 16 * k
            self.e(
                f"(v128.store offset={o} (local.get $dst) "
                f"(v128.xor (v128.load offset={o} (i32.const {TMP})) "
                f"(v128.load offset={o} (i32.const {R}))))"
            )

    def rounds(self, round_fn, column: bool = True, row: bool = True) -> None:
        self.e("(local.set $base (i32.const 1024))")
        if column:
            for grp in range(8):
                self.e(f";; column round {grp}: words {16 * grp}..{16 * grp + 15}")
                for j in range(8):
                    self.e(
                        f"(local.set $q{j} (v128.load offset={16 * grp * 8 + 16 * j} "
                        f"(local.get $base)))"
                    )
                round_fn()
                for j in range(8):
                    self.e(
                        f"(v128.store offset={16 * grp * 8 + 16 * j} (local.get $base) "
                        f"(local.get $q{j}))"
                    )
        if row:
            for grp in range(8):
                self.e(f";; row round {grp}: words {2 * grp},{2 * grp + 1},{2 * grp + 16},...")
                for j in range(8):
                    idx = 2 * grp + 16 * j
                    self.e(f"(local.set $q{j} (v128.load offset={idx * 8} (local.get $base)))")
                round_fn()
                for j in range(8):
                    idx = 2 * grp + 16 * j
                    self.e(f"(v128.store offset={idx * 8} (local.get $base) (local.get $q{j}))")

    # -- the module --------------------------------------------------------
    def build(self, variant: str, bench: bool = False) -> str:
        v = VARIANTS[variant]
        self.out.append("(module")
        self.e('(memory (export "memory") 320)')
        self.e(";; scratch: block_tmp at 0, blockR at 1024; the caller's blocks start at 2048+")
        self.e(
            '(func $fill (export "fill_block") (param $dst i32) (param $prev i32) '
            "(param $ref i32) (param $xor i32)"
        )
        self.e("  (local $base i32)" + (" (local $i i32)" if not v["unrolled"] else ""))
        self.e("  " + " ".join(f"(local $q{j} v128)" for j in range(8)))
        self.e("  (local $b0 v128) (local $b1 v128) (local $d0 v128) (local $d1 v128)")
        self.e("  (local $t0 v128) (local $t1 v128)")
        if v["copy"]:
            (self.copy_unrolled if v["unrolled"] else self.copy_loop)()
        if v["rounds"]:
            rot_alu, interleave, diag = v["rot_alu"], v["interleave"], v["diag"]

            def round_fn():
                if diag == "ref":
                    self.round_pair(rot_alu, interleave)
                else:
                    self.round_legacy(rot_alu)

            self.rounds(round_fn)
        if v["out"]:
            (self.out_unrolled if v["unrolled"] else self.out_loop)()
        if not (v["copy"] or v["rounds"] or v["out"]):
            self.e("(v128.store (local.get $dst) (v128.load (local.get $prev)))")
        self.e(")")
        if bench:
            self.out.append(BENCH)
        self.e('(func (export "blocks") (result i32) (i32.const 128))')
        self.out.append(")")
        return "\n".join(self.out) + "\n"


# The in-module benchmark loop. One `bench` call runs n fill_block calls without
# returning to JS, so a formulation is timed without the ~0.1 us per-call cost
# that would otherwise dominate a small difference.
#
#   bench(base, m, n, scatter) -> seed
#
# scatter=1 picks pseudo-random reference blocks across the m-block arena (the
# way Argon2id really indexes its memory) and walks dst across blocks 16..m-1.
# scatter=0 keeps prev/ref and dst on three fixed blocks: cache-resident, i.e.
# the arithmetic only. with_xor alternates every call in both modes.
BENCH = """
  (func (export "bench") (param $base i32) (param $m i32) (param $n i32) (param $scatter i32)
        (result i32)
    (local $i i32) (local $seed i32) (local $r1 i32) (local $r2 i32) (local $d i32)
    (local.set $seed (i32.const 2712847316))
    (local.set $i (i32.const 0))
    (block $done (loop $lp
      (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
      (if (local.get $scatter)
        (then
          (local.set $seed (i32.add (i32.mul (local.get $seed) (i32.const 1103515245))
                                     (i32.const 12345)))
          (local.set $r1 (i32.rem_u (i32.shr_u (local.get $seed) (i32.const 8)) (local.get $m)))
          (local.set $seed (i32.add (i32.mul (local.get $seed) (i32.const 1103515245))
                                     (i32.const 12345)))
          (local.set $r2 (i32.rem_u (i32.shr_u (local.get $seed) (i32.const 8)) (local.get $m)))
          (local.set $d (i32.add (i32.const 16)
                                 (i32.rem_u (local.get $i)
                                            (i32.sub (local.get $m) (i32.const 16))))))
        (else
          (local.set $r1 (i32.const 1))
          (local.set $r2 (i32.const 2))
          (local.set $d (i32.const 3))))
      (call $fill
        (i32.add (local.get $base) (i32.shl (local.get $d) (i32.const 10)))
        (i32.add (local.get $base) (i32.shl (local.get $r1) (i32.const 10)))
        (i32.add (local.get $base) (i32.shl (local.get $r2) (i32.const 10)))
        (i32.and (local.get $i) (i32.const 1)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $lp)))
    (local.get $seed))
"""


def V(
    diag: str = "ref",
    rot_alu: bool = False,
    interleave: bool = True,
    unrolled: bool = True,
    copy: bool = True,
    out: bool = True,
    rounds: bool = True,
) -> dict:
    return dict(
        diag=diag,
        rot_alu=rot_alu,
        interleave=interleave,
        unrolled=unrolled,
        copy=copy,
        out=out,
        rounds=rounds,
    )


VARIANTS = {
    # the committed kernel
    "simd": V(),
    # what the previous generator emitted, kept for the comparison table
    "legacy": V(diag="old", rot_alu=False, interleave=False, unrolled=False),
    # one change at a time, to show what each is worth
    "legacy_unrolled": V(diag="old", rot_alu=False, interleave=False, unrolled=True),
    "simd_loop_mem": V(rot_alu=False, interleave=True, unrolled=False),
    "simd_rot_alu": V(rot_alu=True),
    "simd_sequential": V(rot_alu=False, interleave=False),
    # ablations: the round core alone, and the copy alone
    "core": V(copy=False, out=False),
    "core_legacy": V(
        diag="old", rot_alu=False, interleave=False, unrolled=False, copy=False, out=False
    ),
    "mem_unrolled": V(unrolled=True, copy=True, out=True, rounds=False),
    "mem_loop": V(unrolled=False, copy=True, out=True, rounds=False),
    "empty": V(copy=False, out=False, rounds=False),
}


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--out", default="wasm/argon2_fill_simd.wat")
    ap.add_argument("--variant", default="simd", choices=sorted(VARIANTS))
    ap.add_argument(
        "--bench", action="store_true", help="append an in-module bench(base, m, n, scatter) loop"
    )
    args = ap.parse_args()

    module = Gen().build(args.variant, args.bench)
    root = Path(__file__).resolve().parent.parent
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix != ".wat":
        raise SystemExit(f"--out must end in .wat, got {out}")
    header = [
        ";; Argon2id fill_block with explicit v128 SIMD, generated by",
        f";; tools/gen_argon2_wat_simd.py (variant {args.variant}).",
        ";; Eight v128 registers hold the 16 words of a round, two u64 each. The",
        ";; column G's pair exactly; the diagonals cost four shuffles in, four out.",
        ";; fBlaMka packs the low halves of both lanes before the widening multiply",
        ";; (i64x2.extmul_low_i32x4_u multiplies i32 lanes 0 and 1), which is where",
        ";; the shuffle port goes; see the generator and bench-fill-inmodule.mjs.",
    ]
    out.write_text("\n".join(header) + "\n" + module)
    print(f"wrote {out} ({len(module.splitlines())} lines, variant {args.variant})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
