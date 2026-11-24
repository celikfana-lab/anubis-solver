/* meatrider_simd.c -- the `meatrider` tier as a 4-lane wasm-SIMD kernel.
 *
 * Same ABI as meatrider_pow.wasm, so the same JavaScript drives either:
 *
 *   data_ptr() -> u32            write the 32-byte randomData here
 *   set_data_length(u32)         must be 32 for this tier
 *   result_hash_ptr() -> u32     the 32-byte digest of the last candidate
 *   result_hash_size() -> u32    32
 *   anubis_work(difficulty, nonce, iterand) -> u32
 *   anubis_work_limited(difficulty, nonce, iterand, limit) -> i32
 *
 * The difference is only how many nonces are in flight. A batch of four
 * consecutive candidates -- nonce + k*iterand for k = 0..3 -- is hashed in
 * four u32 lanes of a v128, so the SHA-256 rounds are shared: one set of
 * instructions does the work of four scalar hashes. Candidates are still
 * tested in sequence order, lane 0 first, so the first nonce that meets the
 * target is exactly the one a scalar scan returns.
 *
 * The challenge context (the fixed header midstate) is built by the reference
 * implementation in src/meatrider/meatrider.c, which this build compiles as a
 * separate translation unit: meatrider_ctx_init() is shared, the two
 * compressions per hash are not. Those are implemented below with v128 ops.
 *
 * No libc: the only thing this file uses is stdint.h and meatrider.h.
 *
 *   clang --target=wasm32 -O3 -msimd128 -nostdlib -Wl,--no-entry \
 *         -I../src/meatrider \
 *         -Wl,--export-memory -Wl,--export=data_ptr \
 *         -Wl,--export=set_data_length -Wl,--export=result_hash_ptr \
 *         -Wl,--export=result_hash_size -Wl,--export=anubis_work \
 *         -Wl,--export=anubis_work_limited \
 *         -o meatrider_simd.wasm meatrider_simd.c ../src/meatrider/meatrider.c
 */
#include <stdint.h>

#include "meatrider.h"
#include "wasm_simd128.h"

/* The same round constants as the reference; kept here because that file's
 * table is static and this translation unit must not include it. */
static const uint32_t MEATRIDER_SIMD_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint8_t buf[64];
static uint32_t buf_len;
/* The digest is built directly as eight 32-bit words: the display order is
 * word-reversed and each word stored little-endian, and wasm is little-endian,
 * so a plain u32 store is exactly the byte sequence meatrider_hash() writes. */
static uint32_t result[8];

static meatrider_ctx ctx;
static uint32_t ctx_bits;      /* the difficulty the context was built for */
static uint8_t ctx_rd[32];     /* ... and the challenge, so a reused module
                                * with a fresh challenge rebuilds */
static int ctx_ready;

uint8_t *data_ptr(void) { return buf; }
void set_data_length(uint32_t n) { buf_len = n > sizeof buf ? (uint32_t)sizeof buf : n; }
uint8_t *result_hash_ptr(void) { return (uint8_t *)result; }
uint32_t result_hash_size(void) { return 32; }

static inline uint32_t load_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           (uint32_t)p[3];
}

static inline uint32_t bswap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0x0000ff00u) | ((x << 8) & 0x00ff0000u) |
           (x << 24);
}

static inline v128_t rotr32v(v128_t x, int n) {
    return wasm_v128_or(wasm_u32x4_shr(x, (uint32_t)n),
                        wasm_i32x4_shl(x, (uint32_t)(32 - n)));
}

static inline v128_t add3(v128_t a, v128_t b, v128_t c) {
    return wasm_i32x4_add(wasm_i32x4_add(a, b), c);
}

static inline v128_t xor3(v128_t a, v128_t b, v128_t c) {
    return wasm_v128_xor(wasm_v128_xor(a, b), c);
}

/* One SHA-256 compression of a 64-byte block into h, for four independent
 * lanes at once. `blk[i]` is big-endian message word i of each lane and
 * `h[i]` is state word i of each lane; both are updated in place. */
static void compress4(v128_t h[8], const v128_t blk[16]) {
    v128_t w[16];
    v128_t a, b, c, d, e, f, g, hh;
    int i;

    for (i = 0; i < 16; i++) w[i] = blk[i];

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

#if defined(__clang__)
#pragma clang loop unroll(full)
#endif
    for (i = 0; i < 64; i++) {
        if (i >= 16) {
            v128_t x = w[(i - 15) & 15];
            v128_t y = w[(i - 2) & 15];
            v128_t s0 = xor3(rotr32v(x, 7), rotr32v(x, 18),
                             wasm_u32x4_shr(x, 3));
            v128_t s1 = xor3(rotr32v(y, 17), rotr32v(y, 19),
                             wasm_u32x4_shr(y, 10));
            w[i & 15] = wasm_i32x4_add(
                w[i & 15],
                add3(s0, w[(i - 7) & 15], s1));
        }
        {
            v128_t S1 = xor3(rotr32v(e, 6), rotr32v(e, 11), rotr32v(e, 25));
            v128_t ch = wasm_v128_bitselect(f, g, e);
            v128_t t1 = add3(hh, S1,
                             wasm_i32x4_add(wasm_u32x4_splat(MEATRIDER_SIMD_K[i]),
                                            wasm_i32x4_add(ch, w[i & 15])));
            v128_t S0 = xor3(rotr32v(a, 2), rotr32v(a, 13), rotr32v(a, 22));
            v128_t maj = wasm_v128_bitselect(wasm_v128_or(a, b),
                                             wasm_v128_and(a, b), c);
            v128_t t2 = wasm_i32x4_add(S0, maj);
            hh = g; g = f; f = e; e = wasm_i32x4_add(d, t1);
            d = c; c = b; b = a; a = wasm_i32x4_add(t1, t2);
        }
    }
    h[0] = wasm_i32x4_add(h[0], a);
    h[1] = wasm_i32x4_add(h[1], b);
    h[2] = wasm_i32x4_add(h[2], c);
    h[3] = wasm_i32x4_add(h[3], d);
    h[4] = wasm_i32x4_add(h[4], e);
    h[5] = wasm_i32x4_add(h[5], f);
    h[6] = wasm_i32x4_add(h[6], g);
    h[7] = wasm_i32x4_add(h[7], hh);
}

/* SHA-256d over one header per lane, written in Bitcoin display order (words
 * reversed, each stored little-endian), exactly like meatrider_hash(). Each
 * lane's eight words are the bytes of its digest in order (wasm is LE). */
static void hash4(const meatrider_ctx *c, const uint32_t nonce[4],
                  uint32_t out[4][8]) {
    v128_t blk[16];
    v128_t h[8];
    uint32_t lane[4];
    int i, k;

    /* block 1: tail[12] || nonce (LE) || 0x80 || zeros || 640-bit length.
     * Only word 3 moves with the nonce; words 0..2 are the fixed tail. */
    blk[0] = wasm_u32x4_splat(load_be32(c->tail + 0));
    blk[1] = wasm_u32x4_splat(load_be32(c->tail + 4));
    blk[2] = wasm_u32x4_splat(load_be32(c->tail + 8));
    blk[3] = wasm_u32x4_make(bswap32(nonce[0]), bswap32(nonce[1]),
                             bswap32(nonce[2]), bswap32(nonce[3]));
    blk[4] = wasm_u32x4_splat(0x80000000u);
    for (i = 5; i < 15; i++) blk[i] = wasm_u32x4_splat(0);
    blk[15] = wasm_u32x4_splat(0x00000280u);      /* 80 * 8 = 640 */

    for (i = 0; i < 8; i++) h[i] = wasm_u32x4_splat(c->mid[i]);
    compress4(h, blk);

    /* block 2: the 32-byte digest1, 0x80, zeros, 256-bit length. digest1 is
     * the big-endian serialisation of h[0..7], so block words 0..7 are h. */
    for (i = 0; i < 8; i++) blk[i] = h[i];
    blk[8] = wasm_u32x4_splat(0x80000000u);
    for (i = 9; i < 15; i++) blk[i] = wasm_u32x4_splat(0);
    blk[15] = wasm_u32x4_splat(0x00000100u);      /* 32 * 8 = 256 */

    for (i = 0; i < 8; i++)
        h[i] = wasm_u32x4_splat(
            i == 0 ? 0x6a09e667u : i == 1 ? 0xbb67ae85u :
            i == 2 ? 0x3c6ef372u : i == 3 ? 0xa54ff53au :
            i == 4 ? 0x510e527fu : i == 5 ? 0x9b05688cu :
            i == 6 ? 0x1f83d9abu : 0x5be0cd19u);
    compress4(h, blk);

    /* display order: byte 4*i..4*i+3 = LE32(h[7-i]); keep that word. */
    for (i = 0; i < 8; i++) {
        wasm_v128_store(lane, h[7 - i]);
        for (k = 0; k < 4; k++) out[k][i] = lane[k];
    }
}

static int has_enough_zero_bits(const uint8_t *h, uint32_t difficulty) {
    uint32_t bytes = difficulty / 8;
    if (bytes > 32) bytes = 32;
    for (uint32_t i = 0; i < bytes; i++)
        if (h[i] != 0) return 0;
    if (difficulty % 8) {
        uint8_t mask = (uint8_t)(0xFF << (8 - difficulty % 8));
        if (h[bytes] & mask) return 0;
    }
    return 1;
}

/* Building the context costs one SHA-256 of the challenge plus one compression,
 * so it is cached across the windows a page asks for. Same policy as the
 * scalar kernel: rebuild only when the challenge or difficulty changed. */
static int prepare(uint32_t difficulty) {
    if (buf_len != 32 || difficulty < 1 || difficulty > 255) return -1;
    if (ctx_ready && ctx_bits == difficulty) {
        uint32_t i;
        for (i = 0; i < 32; i++)
            if (ctx_rd[i] != buf[i]) break;
        if (i == 32) return 0;
    }
    if (meatrider_ctx_init(&ctx, buf, (int)difficulty) != 0) return -1;
    for (uint32_t i = 0; i < 32; i++) ctx_rd[i] = buf[i];
    ctx_bits = difficulty;
    ctx_ready = 1;
    return 0;
}

/* The shared scan. Returns the first nonce (in scan order) whose digest has
 * `difficulty` leading zero bits, or -1. `result` always holds the digest of
 * the last candidate tested, which is also the winning digest on success --
 * the same contract the scalar kernel gives. */
static int scan(uint32_t difficulty, uint32_t nonce, uint32_t iterand,
                uint32_t limit, int limited) {
    uint32_t done = 0;

    if (iterand == 0) iterand = 1;
    if (prepare(difficulty) != 0) return -1;
    if (limited && limit == 0) return -1;

    for (;;) {
        uint32_t n[4];
        uint32_t d[4][8];
        uint32_t lanes = 4;
        uint32_t k;
        int i;

        n[0] = nonce;
        n[1] = nonce + iterand;
        n[2] = nonce + 2u * iterand;
        n[3] = nonce + 3u * iterand;
        hash4(&ctx, n, d);

        if (limited) {
            uint32_t rem = limit - done;
            if (rem < lanes) lanes = rem;
        }
        for (k = 0; k < lanes; k++) {
            if (has_enough_zero_bits((const uint8_t *)d[k], difficulty)) {
                for (i = 0; i < 8; i++) result[i] = d[k][i];
                return (int)n[k];
            }
        }
        /* no winner in this batch: leave the last tested digest, like the
         * scalar kernel leaves the last hash it computed */
        for (i = 0; i < 8; i++) result[i] = d[lanes - 1][i];

        if (limited) {
            done += lanes;
            if (done >= limit) return -1;
        }
        nonce += 4u * iterand;
    }
}

int anubis_work_limited(uint32_t difficulty, uint32_t nonce, uint32_t iterand,
                        uint32_t limit) {
    return scan(difficulty, nonce, iterand, limit, 1);
}

int anubis_work(uint32_t difficulty, uint32_t nonce, uint32_t iterand) {
    return scan(difficulty, nonce, iterand, 0, 0);
}
