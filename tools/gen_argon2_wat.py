#!/usr/bin/env python3
"""gen_argon2_wat.py — the Argon2id block-filling core as straight-line WAT.

Argon2id is memory-hard, not interpreter-bound: unlike HashX there is no VM to
remove, so this is a *faithful* port of `fill_block` from the vendored reference
(`third_party/argon2/ref.c`) with the permutation fully unrolled. What it buys is
the same thing a C compiler buys — no loop bookkeeping, no array indexing, the 16
words of each round living in wasm locals — and what it costs is module size.

    python3 tools/gen_argon2_wat.py            # -> wasm/argon2_fill.wat

Exports:

    fill_block(dst, prev, ref, with_xor)   one 1 KiB block, addresses in bytes
    blocks                                 128 (words per block, for the harness)

Scratch lives at addresses 0 (block_tmp) and 1024 (blockR), so the caller's
blocks must start at 2048 or above. The harness uses 4096.

Correctness is checked against vectors produced by compiling the reference C
itself (`wasm/verify-a2i.mjs` regenerates and compares them).
"""
from __future__ import annotations

import argparse
from pathlib import Path

M32 = 0xFFFFFFFF
TMP = 0
R = 1024
ARENA = 4096

# BLAKE2_ROUND_NOMSG: the eight G calls a round makes on its 16 words
ROUND = [
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
]


class Gen:
    def __init__(self) -> None:
        self.out: list[str] = []
        self.depth = 0

    def e(self, line: str) -> None:
        self.out.append("  " * (2 + self.depth) + line)

    # -- the BlaMka round ------------------------------------------------
    def g(self, a: str, b: str, c: str, d: str) -> None:
        """G(a,b,c,d) with fBlaMka(x,y) = x + y + 2*(x&0xffffffff)*(y&0xffffffff)."""
        for x, y, rot in ((a, b, 32), (c, d, 24), (a, b, 16), (c, d, 63)):
            self.e(f"(local.set $t0 (i64.mul (i64.and (local.get ${x}) (i64.const {M32})) "
                   f"(i64.and (local.get ${y}) (i64.const {M32}))))")
            self.e(f"(local.set ${x} (i64.add (local.get ${x}) (i64.add (local.get ${y}) "
                   f"(i64.shl (local.get $t0) (i64.const 1)))))")
            # the d/c half of the pattern: rotate the other pair against the new value
            other = d if x == a else b
            self.e(f"(local.set ${other} (i64.rotr (i64.xor (local.get ${other}) "
                   f"(local.get ${x})) (i64.const {rot})))")

    def round(self, idx: list[int]) -> None:
        """Load 16 words of blockR, run one BLAKE2 round, store them back."""
        for j, i in enumerate(idx):
            self.e(f"(local.set $v{j} (i64.load offset={8 * i} (local.get $base)))")
        for (a, b, c, d) in ROUND:
            self.g(f"v{a}", f"v{b}", f"v{c}", f"v{d}")
        for j, i in enumerate(idx):
            self.e(f"(i64.store offset={8 * i} (local.get $base) (local.get $v{j}))")

    # -- the module ------------------------------------------------------
    def build(self) -> str:
        e = self.e
        self.out.append("(module")
        e('  (memory (export "memory") 320)')      # 20 MiB: a 19 MiB Argon2 arena + scratch
        e("  ;; scratch: block_tmp at 0, blockR at 1024; the caller's blocks start at 2048+")
        e("")
        e('  (func (export "fill_block") (param $dst i32) (param $prev i32) (param $ref i32) '
          "(param $xor i32)")
        e("    (local $base i32) (local $i i32) (local $a i64) (local $b i64) (local $t0 i64)")
        e("    " + " ".join(f"(local $v{j} i64)" for j in range(16)))
        e("")
        e("    ;; ---- blockR = ref ^ prev; block_tmp = blockR ^ (with_xor ? dst : 0) ----")
        e("    (local.set $base (i32.const 1024))")
        e("    (local.set $i (i32.const 0))")
        e("    (block $copy_done")
        e("      (loop $copy")
        e("        (br_if $copy_done (i32.ge_u (local.get $i) (i32.const 128)))")
        e("        (i64.store")
        e("          (i32.add (local.get $base) (i32.shl (local.get $i) (i32.const 3)))")
        e("          (i64.xor")
        e("            (i64.load (i32.add (local.get $ref) (i32.shl (local.get $i) (i32.const 3))))")
        e("            (i64.load (i32.add (local.get $prev) (i32.shl (local.get $i) (i32.const 3))))))")
        e("        (if (local.get $xor)")
        e("          (then")
        e("            (i64.store")
        e("              (i32.add (i32.const 0) (i32.shl (local.get $i) (i32.const 3)))")
        e("              (i64.xor")
        e("                (i64.load (i32.add (local.get $base) (i32.shl (local.get $i) (i32.const 3))))")
        e("                (i64.load (i32.add (local.get $dst) (i32.shl (local.get $i) (i32.const 3)))))))")
        e("          (else")
        e("            (i64.store")
        e("              (i32.add (i32.const 0) (i32.shl (local.get $i) (i32.const 3)))")
        e("              (i64.load (i32.add (local.get $base) (i32.shl (local.get $i) (i32.const 3)))))))")
        e("        (local.set $i (i32.add (local.get $i) (i32.const 1)))")
        e("        (br $copy)))")
        e("")
        e("    ;; ---- columns: words (16i .. 16i+15) for i in 0..7 ----")
        e("    (local.set $base (i32.const 1024))")
        e("    ;; ---- rows: (2i,2i+1, 2i+16,2i+17, ... 2i+112,2i+113) for i in 0..7 ----")
        # column rounds
        for grp in range(8):
            self.out.append(f"    ;; column round {grp}")
            self.round([16 * grp + j for j in range(16)])
        # row rounds
        for grp in range(8):
            self.out.append(f"    ;; row round {grp}")
            self.round([2 * grp, 2 * grp + 1, 2 * grp + 16, 2 * grp + 17,
                        2 * grp + 32, 2 * grp + 33, 2 * grp + 48, 2 * grp + 49,
                        2 * grp + 64, 2 * grp + 65, 2 * grp + 80, 2 * grp + 81,
                        2 * grp + 96, 2 * grp + 97, 2 * grp + 112, 2 * grp + 113])
        e("")
        e("    ;; ---- dst = block_tmp ^ blockR ----")
        e("    (local.set $i (i32.const 0))")
        e("    (block $out_done")
        e("      (loop $out")
        e("        (br_if $out_done (i32.ge_u (local.get $i) (i32.const 128)))")
        e("        (i64.store")
        e("          (i32.add (local.get $dst) (i32.shl (local.get $i) (i32.const 3)))")
        e("          (i64.xor")
        e("            (i64.load (i32.add (i32.const 0) (i32.shl (local.get $i) (i32.const 3))))")
        e("            (i64.load (i32.add (i32.const 1024) (i32.shl (local.get $i) (i32.const 3))))))")
        e("        (local.set $i (i32.add (local.get $i) (i32.const 1)))")
        e("        (br $out)))")
        e("  )")
        e("")
        e('  (func (export "blocks") (result i32) (i32.const 128))')
        e('  (global (export "arena") i32 (i32.const ' + str(ARENA) + '))')
        self.out.append(")")
        return "\n".join(self.out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="wasm/argon2_fill.wat")
    args = ap.parse_args()

    module = Gen().build()
    root = Path(__file__).resolve().parent.parent
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    header = (";; Argon2id fill_block as straight-line WAT, generated by "
              "tools/gen_argon2_wat.py\n"
              ";; from third_party/argon2/ref.c: one 1 KiB block, 8 column rounds + 8 row\n"
              ";; rounds, BlaMka (x + y + 2*(x&0xffffffff)*(y&0xffffffff)) unrolled.\n")
    out.write_text(header + module)
    print(f"wrote {out} ({len(module.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
