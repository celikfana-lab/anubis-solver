#!/usr/bin/env python3
"""
Generate the `meatrider` tier's x86-64 assembly from the `sha256` tier's.

The tier is SHA-256d over a real 80-byte Bitcoin block header: header bytes
0..63 are fixed for a challenge and precompressed into a midstate, only the
16-byte second block moves with the nonce, and the second SHA-256 is over the
32-byte first digest. So one hash is two single-block compressions and the
kernels it needs are exactly the ones the `sha256` tier already has:

    meatrider_compress8_avx2(mid, tails[8][64], out[8][32])
    meatrider_compress16_avx512(mid, tails[16][64], out[16][32])
    meatrider_block_shani(state[8], block[64])

This script re-emits them from tools/gen_avx2_s.py, tools/gen_avx512_s.py and
src/cpu/shani.s with the meatrider symbol and a meatrider header, so there is
one instruction sequence to review, not two. The copies exist so the two tiers
can diverge: fusing the two compressions of a Bitcoin hash into one kernel is a
`meatrider` change and must not disturb the `sha256` tier.

Usage:
    python3 tools/gen_meatrider_s.py          # rewrite the three .s files
    python3 tools/gen_meatrider_s.py --check  # fail if they are out of date
"""

import argparse
import importlib.util
import sys
import warnings
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent

MR = "meatrider"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with warnings.catch_warnings():
        # the generators carry asm macros like "\dst" in non-raw strings; that
        # is their business and it is harmless here
        warnings.simplefilter("ignore", SyntaxWarning)
        spec.loader.exec_module(module)
    return module


def strip_header(text: str) -> str:
    """Everything from the first `.section` on: the code, without its comment."""
    marker = text.index("    .section")
    return text[marker:]


def build_avx2(gen) -> str:
    parts = ["    .section .rodata\n    .align 32\n.Lavx2_kb:\n", gen.emit_k(),
             gen.PROLOGUE, gen.emit_loadw(),
             "\n    /* message schedule */", gen.emit_sched(),
             "\n    /* initial state */", gen.emit_state_init(),
             "\n    /* 64 rounds, register roles rotated */",
             gen.emit_rounds(), gen.emit_epilogue()]
    body = "\n".join(parts)
    return body.replace("sha256_compress8_avx2", "meatrider_compress8_avx2")


def build_avx512(gen) -> str:
    parts = ["    .section .rodata\n    .align 64\n.Lavx512_kb:\n", gen.emit_k(),
             gen.PROLOGUE, gen.emit_loadw(),
             "\n    /* initial state */", gen.emit_state_init(),
             "\n    /* 64 rounds: schedule updated in place, roles rotated */",
             gen.emit_rounds(), gen.emit_epilogue()]
    body = "\n".join(parts)
    return body.replace("sha256_compress16_avx512",
                        "meatrider_compress16_avx512")


def build_shani() -> str:
    src = (ROOT / "src" / "cpu" / "shani.s").read_text()
    return strip_header(src).replace("sha256_block_shani",
                                     "meatrider_block_shani")


HEADER_AVX2 = """\
/*
 * meatrider_avx2.s — 8-way AVX2 SHA-256 compression, for the `meatrider` tier.
 *
 * Re-emitted from tools/gen_avx2_s.py by tools/gen_meatrider_s.py, so this is
 * the same hand-written instruction sequence the `sha256` tier runs, under the
 * meatrider symbol. One hash of the tier is two compressions -- the header's
 * block 1 from the shared midstate, then block 2 built from the first digest
 * and the SHA-256 IV -- and meatrider_hash8_avx2() in meatrider_simd.c calls
 * this once for each pass.
 *
 *   void meatrider_compress8_avx2(const uint32_t mid[8],
 *                                 const uint8_t tails[8][64],
 *                                 uint8_t out[8][32]);
 *
 * Each lane compresses one padded 64-byte block from a shared midstate and
 * writes the 32-byte big-endian digest.
 *
 * The copy exists so the two tiers can diverge: fusing both compressions of a
 * Bitcoin hash into one kernel is a meatrider change, and the `sha256` tier's
 * kernel must not move under it.
 */

"""

HEADER_AVX512 = """\
/*
 * meatrider_avx512.s — 16-way AVX-512 SHA-256 compression, for `meatrider`.
 *
 * Re-emitted from tools/gen_avx512_s.py by tools/gen_meatrider_s.py: the same
 * hand-written sequence the `sha256` tier runs, under the meatrider symbol.
 * One hash of the tier is two compressions, so meatrider_hash16_avx512() calls
 * this once for the header's block 1 and once for block 2. Requires AVX-512F;
 * the driver checks the CPU before choosing it.
 *
 *   void meatrider_compress16_avx512(const uint32_t mid[8],
 *                                    const uint8_t tails[16][64],
 *                                    uint8_t out[16][32]);
 *
 * Each lane compresses one padded 64-byte block from a shared midstate and
 * writes the 32-byte big-endian digest. The message schedule lives in
 * zmm16..zmm31, so the round loop touches no stack at all.
 */

"""

HEADER_SHANI = """\
/*
 * meatrider_shani.s — SHA-256 single-block compression via Intel SHA
 * extensions, for the `meatrider` tier.
 *
 * Re-emitted from src/cpu/shani.s by tools/gen_meatrider_s.py: the same
 * hand-written sequence the `sha256` tier runs, under the meatrider symbol.
 *
 *   void meatrider_block_shani(uint32_t state[8], const uint8_t block[64]);
 *
 * Folds one 64-byte block into an existing midstate (state is updated in
 * place), which is exactly one of the two compressions a Bitcoin hash needs:
 * meatrider_hash_shani() calls it with the header midstate and block 1, then
 * with the SHA-256 IV and block 2. About 80 cycles per block against roughly
 * 940 for the portable C compression.
 *
 * Written for the System V AMD64 ABI; no stack is used. State layout as the
 * SHA instructions want it: xmm1 = (A, B, E, F), xmm2 = (C, D, G, H).
 */

"""

FILES = [
    ("src/meatrider/meatrider_avx2.s", HEADER_AVX2, ("gen_avx2_s.py", "avx2")),
    ("src/meatrider/meatrider_avx512.s", HEADER_AVX512,
     ("gen_avx512_s.py", "avx512")),
    ("src/meatrider/meatrider_shani.s", HEADER_SHANI, None),
]


def generate() -> dict:
    avx2 = load("gen_avx2_s", TOOLS / "gen_avx2_s.py")
    avx512 = load("gen_avx512_s", TOOLS / "gen_avx512_s.py")
    out = {}
    for name, header, how in FILES:
        if how is None:
            body = build_shani()
        elif how[1] == "avx2":
            body = build_avx2(avx2)
        else:
            body = build_avx512(avx512)
        out[name] = header + body
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the checked-in files differ")
    args = ap.parse_args()

    stale = 0
    for name, text in generate().items():
        path = ROOT / name
        if args.check:
            current = path.read_text() if path.exists() else ""
            if current != text:
                print(f"stale: {name} (run tools/gen_meatrider_s.py)")
                stale += 1
        else:
            path.write_text(text)
            print(f"wrote {name}")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
