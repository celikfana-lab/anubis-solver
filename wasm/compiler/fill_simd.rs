//! Argon2id fill_block, explicit wasm SIMD (`v128`), hand-written.
//!
//! Two u64 per vector register: q0=[w0,w1], q1=[w2,w3], ... q7=[w14,w15]. The
//! scalar round's G(i, i+4, i+8, i+12) for i=0,1 pairs up as one vector G over
//! (q0,q2,q4,q6), and i=2,3 as (q1,q3,q5,q7) — exact 2x. The diagonal G's cross
//! lanes, so they need the same alignr-style shuffles the C SSD2 path uses.
//!
//!   rustc --target wasm32-unknown-unknown --crate-type=cdylib -C opt-level=3 \
//!         -C panic=abort -C lto=yes -C target-feature=+simd128 \
//!         -o fill_simd_hand.wasm fill_simd.rs
#![no_std]
#![allow(clippy::missing_safety_doc)]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(target_arch = "wasm32")]
use core::arch::wasm32::*;

// ---- byte shuffles for i8x16.shuffle ----

#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn lo32(x: v128) -> v128 {
    i8x16_shuffle::<0, 1, 2, 3, 8, 9, 10, 11, 0, 1, 2, 3, 8, 9, 10, 11>(x, x)
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn rotr32(x: v128) -> v128 {
    i8x16_shuffle::<4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11>(x, x)
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn rotr24(x: v128) -> v128 {
    i8x16_shuffle::<3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10>(x, x)
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn rotr16(x: v128) -> v128 {
    i8x16_shuffle::<2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9>(x, x)
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn rotr63(x: v128) -> v128 {
    v128_xor(i64x2_shl(x, 1), i64x2_shr(x, 63))
}

/// fBlaMka on two lanes: x + y + 2*((x&0xffffffff)*(y&0xffffffff)).
/// extmul_low on the gathered low halves gives the two 32x32->64 products.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn blamka(x: v128, y: v128) -> v128 {
    let z = i64x2_extmul_low_i32x4(lo32(x), lo32(y));
    i64x2_add(i64x2_add(x, y), i64x2_add(z, z))
}

/// G on four 2-lane values, returned in the same order (two independent G's).
#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn g(a: v128, b: v128, c: v128, d: v128) -> (v128, v128, v128, v128) {
    let a = blamka(a, b);
    let d = rotr32(v128_xor(d, a));
    let c = blamka(c, d);
    let b = rotr24(v128_xor(b, c));
    let a = blamka(a, b);
    let d = rotr16(v128_xor(d, a));
    let c = blamka(c, d);
    let b = rotr63(v128_xor(b, c));
    (a, b, c, d)
}

/// One 16-word BLAKE2 round on eight pair registers.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn round16(q: &mut [v128; 8]) {
    // columns: G(i, i+4, i+8, i+12) for i = 0,1 then 2,3 — exact 2x pairing
    let (a, b, c, d) = g(q[0], q[2], q[4], q[6]);
    q[0] = a; q[2] = b; q[4] = c; q[6] = d;
    let (a, b, c, d) = g(q[1], q[3], q[5], q[7]);
    q[1] = a; q[3] = b; q[5] = c; q[7] = d;

    // diagonals. G(0,5,10,15)+G(1,6,11,12): B = [w5,w6] = q2.hi ++ q3.lo,
    // D = [w15,w12] = q7.hi ++ q6.lo. G(2,7,8,13)+G(3,4,9,14): B = q3.hi ++ q4.lo,
    // D = [w13,w8]... derived the same way from the C DIAGONALIZE macro.
    const HI_LO: unsafe fn(v128, v128) -> v128 =
        |x, y| i8x16_shuffle::<8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23>(x, y);
    const KEEP_HI: unsafe fn(v128, v128) -> v128 =
        |x, y| i8x16_shuffle::<0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23>(x, y);
    const HI_KEEP: unsafe fn(v128, v128) -> v128 =
        |x, y| i8x16_shuffle::<8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31>(x, y);

    let (a, b, c, d) = g(q[0], HI_LO(q[2], q[3]), q[5], HI_LO(q[7], q[6]));
    q[0] = a;
    q[2] = KEEP_HI(q[2], b);
    q[3] = HI_KEEP(b, q[3]);
    q[5] = c;
    q[7] = KEEP_HI(q[7], d);
    q[6] = HI_KEEP(d, q[6]);

    let (a, b, c, d) = g(q[1], HI_LO(q[3], q[4]), q[6], HI_LO(q[0], q[7]));
    q[1] = a;
    q[3] = KEEP_HI(q[3], b);
    q[4] = HI_KEEP(b, q[4]);
    q[6] = c;
    q[0] = KEEP_HI(q[0], d);
    q[7] = HI_KEEP(d, q[7]);
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn load_pairs(base: *const u64, start: usize) -> [v128; 8] {
    let mut q = [i64x2_splat(0); 8];
    for i in 0..8 {
        q[i] = v128_load(base.add(start + 2 * i) as *const v128);
    }
    q
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
unsafe fn store_pairs(base: *mut u64, start: usize, q: &[v128; 8]) {
    for i in 0..8 {
        v128_store(base.add(start + 2 * i) as *mut v128, q[i]);
    }
}

/// Same contract as the scalar fill_block.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn fill_block_simd(dst: *mut u64, prev: *const u64, rf: *const u64, with_xor: u32) {
    // blockR = ref ^ prev, kept in a 128-word scratch (tmp is the other half)
    let mut tmp = [0u64; 128];
    let mut rv = [0u64; 128];
    for i in 0..128 {
        let x = *rf.add(i) ^ *prev.add(i);
        rv[i] = x;
        tmp[i] = if with_xor != 0 { x ^ *dst.add(i) } else { x };
    }

    for grp in 0..8 {
        let mut q = load_pairs(rv.as_ptr(), 16 * grp);
        round16(&mut q);
        store_pairs(rv.as_mut_ptr(), 16 * grp, &q);
    }

    // rows: (2i, 2i+1, 2i+16, 2i+17, ... 2i+112, 2i+113) — gather into pairs then
    // shuffle back. Each row is 16 words: pairs (2i,2i+1), (2i+16,2i+17), ...
    for grp in 0..8 {
        let mut q = [i64x2_splat(0); 8];
        for j in 0..8 {
            let a = rv[2 * grp + 16 * j];
            let b = rv[2 * grp + 16 * j + 1];
            q[j] = v128_load([a, b].as_ptr() as *const v128);
        }
        round16(&mut q);
        for j in 0..8 {
            let mut out = [0u64; 2];
            v128_store(out.as_mut_ptr() as *mut v128, q[j]);
            rv[2 * grp + 16 * j] = out[0];
            rv[2 * grp + 16 * j + 1] = out[1];
        }
    }

    for i in 0..128 {
        *dst.add(i) = tmp[i] ^ rv[i];
    }
}
