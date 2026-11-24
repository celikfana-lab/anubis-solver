#!/usr/bin/env python3
"""Generate meatrider.ptx -- the PTX kernel for the `meatrider` tier.

`meatrider` hashes a real 80-byte Bitcoin block header twice with SHA-256.
Bytes 0..63 of the header are fixed for a challenge, so the host passes their
midstate (`mid[8]`); bytes 64..75 (`tail[12]`) and the 4-byte little-endian
nonce are the only moving part of the first block:

    block1 = tail[12] || nonce(le32) || 0x80 || zeros || 0x02 0x80
    digest1 = SHA-256(mid, block1)              (8 words, big-endian bytes)
    block2 = digest1 || 0x80 || zeros || 0x01 0x00
    h2 = SHA-256(IV, block2)
    out[4*i .. 4*i+3] = little-endian h2[7-i]   (Bitcoin display order)

The display order matters: the leading zero bits of those 32 bytes are the
difficulty test. The finalize code therefore byteswaps h2[7-i] into the
big-endian display word and then uses the same leading-zero-bit test as
sha256_opt.ptx.

Why a generator: the 16-word message schedule must live in named registers and
the 64 rounds are unrolled, for both compressions. ILP interleaves independent
nonce lanes. Both are mechanical, so the PTX lives here and the result is
checked in.

Usage:
    python3 tools/gen_meatrider_ptx.py [--ilp 1|2|4] > src/meatrider/meatrider.ptx

The committed kernel is generated with --ilp 1.
"""

import argparse

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

STATE = ["a", "b", "c", "d", "e", "f", "g", "h"]


def generate(ilp: int) -> str:
    out = []
    w = out.append

    w("/*")
    w(" * meatrider.ptx -- SHA-256d over an 80-byte Bitcoin block header.")
    w(" *")
    w(" * GENERATED FILE -- do not edit. Regenerate with:")
    w(f" *     python3 tools/gen_meatrider_ptx.py --ilp {ilp} > src/meatrider/meatrider.ptx")
    w(" *")
    w(f" * One thread hashes {ilp} independent nonce(s) (ILP={ilp}). The")
    w(" * 16-word message schedule is held in registers and the 64 rounds of")
    w(" * BOTH compressions are fully unrolled; no local memory is used.")
    w(" *")
    w(" * Parameters:")
    w(" *   mid0..mid7  SHA-256 state after header bytes 0..63")
    w(" *   tail0..2    header bytes 64..75, three little-endian u32 words")
    w(" *   difficulty  leading zero bits of the display-order digest")
    w(" *   base, count nonce range is [base, base+count)")
    w(" *   results_ptr struct results {")
    w(" *                   u32 count; u32 pad[3];")
    w(" *                   u32 nonces[8];")
    w(" *                   u32 hashes[8][8];   (display-order words, BE)")
    w(" *               };  -- same layout as sha256_opt.ptx")
    w(" */")
    w("")
    w(".version 7.5")
    w(".target sm_75")
    w(".address_size 64")
    w("")
    w(".visible .entry meatrider_kernel(")
    w("    .param .u32 mid0, .param .u32 mid1, .param .u32 mid2, .param .u32 mid3,")
    w("    .param .u32 mid4, .param .u32 mid5, .param .u32 mid6, .param .u32 mid7,")
    w("    .param .u32 tail0, .param .u32 tail1, .param .u32 tail2,")
    w("    .param .u32 difficulty,")
    w("    .param .u32 base,")
    w("    .param .u32 count,")
    w("    .param .u64 results_ptr")
    w(") {")
    w("    .reg .pred %p, %pd;")
    w("    .reg .u32 %mid0, %mid1, %mid2, %mid3, %mid4, %mid5, %mid6, %mid7;")
    w("    .reg .u32 %tail0, %tail1, %tail2, %difficulty, %base, %count;")
    w("    .reg .u64 %res;")
    w("    .reg .u32 %nt, %ct, %tx, %idx, %first;")
    w("    .reg .u32 %nbits, %fullw, %remb, %amt, %ok, %slot, %off;")
    w("    .reg .u32 %s0, %s1, %x, %ch, %maj, %t1, %t2;")
    w("    .reg .u32 %tt0, %tt1, %tt2;")
    w("    .reg .u64 %rd;")
    for u in range(ilp):
        regs = [f"%{s}{u}" for s in STATE]
        regs += [f"%w{u}_{k}" for k in range(16)]
        regs += [f"%n{u}", f"%fi{u}"]
        regs += [f"%o{u}_{k}" for k in range(8)]
        w("    .reg .u32 " + ", ".join(regs) + ";")
        w(f"    .reg .pred %pact{u};")
    w("")

    for name in ["mid0", "mid1", "mid2", "mid3", "mid4", "mid5", "mid6", "mid7",
                 "tail0", "tail1", "tail2", "difficulty", "base", "count"]:
        w(f"    ld.param.u32 %{name}, [{name}];")
    w("    ld.param.u64 %res, [results_ptr];")
    w("")
    w("    mov.u32 %nt, %ntid.x;")
    w("    mov.u32 %ct, %ctaid.x;")
    w("    mov.u32 %tx, %tid.x;")
    w("    mad.lo.u32 %idx, %ct, %nt, %tx;")
    w(f"    mul.lo.u32 %first, %idx, {ilp};")
    w("    setp.ge.u32 %p, %first, %count;")
    w("    @%p bra BB_DONE;")
    w("")
    w("    /* difficulty is a leading-zero-BIT count (no nibble conversion) */")
    w("    mov.u32 %nbits, %difficulty;")
    w("    shr.u32 %fullw, %nbits, 5;")
    w("    and.b32 %remb, %nbits, 31;")
    w("    mov.u32 %amt, 32;")
    w("    sub.u32 %amt, %amt, %remb;")
    w("")
    w("    /* the tail words are identical for every nonce: byteswap once */")
    w("    /* (block words are big-endian, the params are little-endian) */")
    bswap(w, "%tt0", "%tail0")
    bswap(w, "%tt1", "%tail1")
    bswap(w, "%tt2", "%tail2")
    w("")

    # ---- lane init: block1 schedule and midstate ----
    for u in range(ilp):
        w(f"    /* ---- lane {u} init, block 1 ---- */")
        w(f"    add.u32 %n{u}, %base, %first;")
        w(f"    add.u32 %n{u}, %n{u}, {u};")
        w(f"    add.u32 %fi{u}, %first, {u};")
        w(f"    setp.lt.u32 %pact{u}, %fi{u}, %count;")
        w(f"    mov.u32 %w{u}_0, %tt0;")
        w(f"    mov.u32 %w{u}_1, %tt1;")
        w(f"    mov.u32 %w{u}_2, %tt2;")
        bswap(w, f"%w{u}_3", f"%n{u}")
        w(f"    mov.u32 %w{u}_4, 0x80000000;")
        for k in range(5, 15):
            w(f"    mov.u32 %w{u}_{k}, 0;")
        w(f"    mov.u32 %w{u}_15, 640;")
        for k, s in enumerate(STATE):
            w(f"    mov.u32 %{s}{u}, %mid{k};")
        w("")

    # ---- compression 1: 64 rounds, lanes interleaved ----
    w(f"    /* ---- compression 1: 64 rounds, {ilp} lane(s) interleaved ---- */")
    for i in range(64):
        for u in range(ilp):
            emit_round(w, u, i)
    w("")

    # ---- lane setup for compression 2 ----
    for u in range(ilp):
        w(f"    /* ---- lane {u} init, block 2 ---- */")
        for k in range(8):
            w(f"    add.u32 %o{u}_{k}, %mid{k}, %{STATE[k]}{u};")
        # block2's first 8 words ARE the big-endian digest1 words, i.e. h1.
        for k in range(8):
            w(f"    mov.u32 %w{u}_{k}, %o{u}_{k};")
        w(f"    mov.u32 %w{u}_8, 0x80000000;")
        for k in range(9, 15):
            w(f"    mov.u32 %w{u}_{k}, 0;")
        w(f"    mov.u32 %w{u}_15, 256;")
        for k, s in enumerate(STATE):
            w(f"    mov.u32 %{s}{u}, 0x{IV[k]:08x};")
        w("")

    # ---- compression 2: 64 rounds, lanes interleaved ----
    w(f"    /* ---- compression 2: 64 rounds, {ilp} lane(s) interleaved ---- */")
    for i in range(64):
        for u in range(ilp):
            emit_round(w, u, i)
    w("")

    # ---- finalize each lane ----
    for u in range(ilp):
        w(f"    /* ---- lane {u} finalize: display order + leading-zero test ---- */")
        for k in range(8):
            w(f"    add.u32 %o{u}_{k}, 0x{IV[k]:08x}, %{STATE[k]}{u};")
        # out[4*i] = LE bytes of h2[7-i], so the display word i is
        # byteswap(h2[7-i]) read big-endian. Swap in pairs through the two
        # free tail temps (%tt0/%tt1) so the in-place reversal cannot clobber
        # a word that has not been moved yet.
        for j in range(4):
            bswap(w, "%tt0", f"%o{u}_{7 - j}")
            bswap(w, "%tt1", f"%o{u}_{j}")
            w(f"    mov.u32 %o{u}_{j}, %tt0;")
            w(f"    mov.u32 %o{u}_{7 - j}, %tt1;")
        w(f"    @!%pact{u} bra L{u}_DONE;")
        w("    mov.u32 %ok, 1;")
        for j in range(8):
            w(f"    setp.ge.u32 %p, %fullw, {j + 1};")
            w(f"    @!%p bra L{u}_SK{j};")
            w(f"    setp.ne.u32 %pd, %o{u}_{j}, 0;")
            w(f"    @%pd bra L{u}_FAIL;")
            w(f"L{u}_SK{j}:")
            w(f"    setp.eq.u32 %p, %fullw, {j};")
            w(f"    @!%p bra L{u}_SP{j};")
            w("    setp.eq.u32 %pd, %remb, 0;")
            w(f"    @%pd bra L{u}_SP{j};")
            w(f"    shr.u32 %t1, %o{u}_{j}, %amt;")
            w("    setp.ne.u32 %pd, %t1, 0;")
            w(f"    @%pd bra L{u}_FAIL;")
            w(f"L{u}_SP{j}:")
        w(f"    bra L{u}_CHK_DONE;")
        w(f"L{u}_FAIL:")
        w("    mov.u32 %ok, 0;")
        w(f"L{u}_CHK_DONE:")
        w("    setp.eq.u32 %p, %ok, 0;")
        w(f"    @%p bra L{u}_DONE;")
        w("    atom.global.add.u32 %slot, [%res], 1;")
        w("    setp.ge.u32 %p, %slot, 8;")
        w(f"    @%p bra L{u}_DONE;")
        w("    mul.lo.u32 %off, %slot, 4;")
        w("    add.u32 %off, %off, 16;")
        w("    cvt.u64.u32 %rd, %off;")
        w("    add.u64 %rd, %res, %rd;")
        w(f"    st.global.u32 [%rd], %n{u};")
        w("    mul.lo.u32 %off, %slot, 32;")
        w("    add.u32 %off, %off, 48;")
        w("    cvt.u64.u32 %rd, %off;")
        w("    add.u64 %rd, %res, %rd;")
        for k in range(8):
            w(f"    st.global.u32 [%rd+{4 * k}], %o{u}_{k};")
        w(f"L{u}_DONE:")
        w("")

    w("BB_DONE:")
    w("    ret;")
    w("}")
    w("")
    return "\n".join(out)


def bswap(w, dst, src):
    """dst = byteswap(src). Safe in place: dst is written last."""
    w(f"    and.b32 %x, {src}, 0xff;")
    w("    shl.b32 %x, %x, 24;")
    w(f"    and.b32 %t1, {src}, 0xff00;")
    w("    shl.b32 %t1, %t1, 8;")
    w("    or.b32 %x, %x, %t1;")
    w(f"    shr.b32 %t1, {src}, 8;")
    w("    and.b32 %t1, %t1, 0xff00;")
    w("    or.b32 %x, %x, %t1;")
    w(f"    shr.b32 %t1, {src}, 24;")
    w("    or.b32 %x, %x, %t1;")
    w(f"    mov.u32 {dst}, %x;")


def emit_round(w, u, i):
    j = i & 15
    if i >= 16:
        j1 = (i + 1) & 15
        j14 = (i + 14) & 15
        j9 = (i + 9) & 15
        w(f"    shf.r.wrap.b32 %s0, %w{u}_{j1}, %w{u}_{j1}, 7;")
        w(f"    shf.r.wrap.b32 %x, %w{u}_{j1}, %w{u}_{j1}, 18;")
        w("    xor.b32 %s0, %s0, %x;")
        w(f"    shr.b32 %x, %w{u}_{j1}, 3;")
        w("    xor.b32 %s0, %s0, %x;")
        w(f"    shf.r.wrap.b32 %s1, %w{u}_{j14}, %w{u}_{j14}, 17;")
        w(f"    shf.r.wrap.b32 %x, %w{u}_{j14}, %w{u}_{j14}, 19;")
        w("    xor.b32 %s1, %s1, %x;")
        w(f"    shr.b32 %x, %w{u}_{j14}, 10;")
        w("    xor.b32 %s1, %s1, %x;")
        w(f"    add.u32 %w{u}_{j}, %w{u}_{j}, %s0;")
        w(f"    add.u32 %w{u}_{j}, %w{u}_{j}, %w{u}_{j9};")
        w(f"    add.u32 %w{u}_{j}, %w{u}_{j}, %s1;")
    w(f"    shf.r.wrap.b32 %s1, %e{u}, %e{u}, 6;")
    w(f"    shf.r.wrap.b32 %x, %e{u}, %e{u}, 11;")
    w("    xor.b32 %s1, %s1, %x;")
    w(f"    shf.r.wrap.b32 %x, %e{u}, %e{u}, 25;")
    w("    xor.b32 %s1, %s1, %x;")
    w(f"    and.b32 %ch, %e{u}, %f{u};")
    w(f"    not.b32 %x, %e{u};")
    w(f"    and.b32 %x, %x, %g{u};")
    w("    xor.b32 %ch, %ch, %x;")
    w(f"    add.u32 %t1, %h{u}, %s1;")
    w("    add.u32 %t1, %t1, %ch;")
    w(f"    add.u32 %t1, %t1, 0x{K[i]:08x};")
    w(f"    add.u32 %t1, %t1, %w{u}_{j};")
    w(f"    shf.r.wrap.b32 %s0, %a{u}, %a{u}, 2;")
    w(f"    shf.r.wrap.b32 %x, %a{u}, %a{u}, 13;")
    w("    xor.b32 %s0, %s0, %x;")
    w(f"    shf.r.wrap.b32 %x, %a{u}, %a{u}, 22;")
    w("    xor.b32 %s0, %s0, %x;")
    w(f"    and.b32 %maj, %a{u}, %b{u};")
    w(f"    and.b32 %x, %a{u}, %c{u};")
    w("    xor.b32 %maj, %maj, %x;")
    w(f"    and.b32 %x, %b{u}, %c{u};")
    w("    xor.b32 %maj, %maj, %x;")
    w("    add.u32 %t2, %s0, %maj;")
    w(f"    mov.u32 %h{u}, %g{u};")
    w(f"    mov.u32 %g{u}, %f{u};")
    w(f"    mov.u32 %f{u}, %e{u};")
    w(f"    add.u32 %e{u}, %d{u}, %t1;")
    w(f"    mov.u32 %d{u}, %c{u};")
    w(f"    mov.u32 %c{u}, %b{u};")
    w(f"    mov.u32 %b{u}, %a{u};")
    w(f"    add.u32 %a{u}, %t1, %t2;")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ilp", type=int, default=1, choices=(1, 2, 4))
    args = ap.parse_args()
    print(generate(args.ilp))


if __name__ == "__main__":
    main()
