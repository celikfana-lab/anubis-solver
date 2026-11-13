//! Argon2id fill_block, compiled to wasm by rustc — the "let a compiler do it"
//! side of the comparison against the hand-written WAT in ../argon2_fill.wat.
//!
//!   rustc --target wasm32-unknown-unknown --crate-type=cdylib \
//!         -C opt-level=3 -C panic=abort -C lto=yes -o fill_scalar.wasm fill.rs
//!   rustc ... -C target-feature=+simd128 -o fill_simd.wasm fill.rs
//!
//! Measured (see ../bench-compiler.mjs): this is 2x faster than the hand-written
//! WAT and 7x smaller, which is the answer to "should I hand-write wasm?".
#![no_std]
#![allow(clippy::missing_safety_doc)]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

const M32: u64 = 0xFFFF_FFFF;

#[inline(always)]
fn blamka(x: u64, y: u64) -> u64 {
    let xy = (x & M32).wrapping_mul(y & M32);
    x.wrapping_add(y).wrapping_add(xy.wrapping_mul(2))
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[inline(always)]
fn round(v: &mut [u64; 16]) {
    g(v, 0, 4, 8, 12);
    g(v, 1, 5, 9, 13);
    g(v, 2, 6, 10, 14);
    g(v, 3, 7, 11, 15);
    g(v, 0, 5, 10, 15);
    g(v, 1, 6, 11, 12);
    g(v, 2, 7, 8, 13);
    g(v, 3, 4, 9, 14);
}

/// One 1 KiB block: `dst = (ref ^ prev [^ dst])  mixed`, as ref.c does it.
#[no_mangle]
pub unsafe extern "C" fn fill_block(dst: *mut u64, prev: *const u64, rf: *const u64, with_xor: u32) {
    let mut rv = [0u64; 128];
    let mut tmp = [0u64; 128];

    for i in 0..128 {
        let x = *rf.add(i) ^ *prev.add(i);
        rv[i] = x;
        tmp[i] = if with_xor != 0 { x ^ *dst.add(i) } else { x };
    }

    for grp in 0..8 {
        let mut v = [0u64; 16];
        v.copy_from_slice(&rv[16 * grp..16 * grp + 16]);
        round(&mut v);
        rv[16 * grp..16 * grp + 16].copy_from_slice(&v);
    }

    for grp in 0..8 {
        let mut v = [0u64; 16];
        for (j, k) in [0, 1, 16, 17, 32, 33, 48, 49, 64, 65, 80, 81, 96, 97, 112, 113]
            .iter()
            .enumerate()
        {
            v[j] = rv[2 * grp + k];
        }
        round(&mut v);
        for (j, k) in [0, 1, 16, 17, 32, 33, 48, 49, 64, 65, 80, 81, 96, 97, 112, 113]
            .iter()
            .enumerate()
        {
            rv[2 * grp + k] = v[j];
        }
    }

    for i in 0..128 {
        *dst.add(i) = tmp[i] ^ rv[i];
    }
}
