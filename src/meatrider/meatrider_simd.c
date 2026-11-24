/* meatrider_simd.c -- the x86-64 kernels of the `meatrider` tier.
 *
 * A hash of the tier is two single-block SHA-256 compressions:
 *
 *   h1 = compress(header midstate, block1(nonce))
 *   h2 = compress(SHA-256 IV,     block2(h1))
 *   digest = reverse_words(h2)            <- Bitcoin display order
 *
 * so both vector paths are "run one compression kernel twice per lane group".
 * The kernels themselves are the `sha256` tier's instruction sequences under
 * meatrider symbols (tools/gen_meatrider_s.py); what this file adds is the
 * Bitcoin part: which bytes block 1 and block 2 are, and that the digest is
 * reversed before anybody compares it to a target.
 *
 * Rates on the machine this was written on (i7-1260P, one thread, difficulty
 * 16): see tools/meatrider_backends.py and the `meatrider` section of SPEED.md.
 * The scalar compression runs at ~0.91 MHash/s per core; SHA-NI takes that to
 * the tens of millions, and the AVX2 path does eight nonces per pair of
 * kernels.
 */

#include "meatrider_simd.h"

#ifdef MEATRIDER_HAVE_SIMD

#include <stdlib.h>
#include <string.h>

extern void meatrider_block_shani(uint32_t state[8], const uint8_t block[64]);
extern void meatrider_compress8_avx2(const uint32_t mid[8],
                                     const uint8_t tails[8][64],
                                     uint8_t out[8][32]);
extern void meatrider_compress16_avx512(const uint32_t mid[8],
                                        const uint8_t tails[16][64],
                                        uint8_t out[16][32]);

/* ------------------------------------------------------------------ */
/* Availability                                                        */
/* ------------------------------------------------------------------ */

static int env_off(const char *name) {
    const char *v = getenv(name);
    return v != NULL && v[0] != '\0' && v[0] != '0';
}

int meatrider_shani_available(void) {
    static int cached = -1;
    if (cached < 0) {
        if (env_off("ANUBIS_NO_SHANI")) {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("sha") ? 1 : 0;
        }
    }
    return cached;
}

int meatrider_avx2_available(void) {
    static int cached = -1;
    if (cached < 0) {
        if (env_off("ANUBIS_NO_AVX2")) {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("avx2") ? 1 : 0;
        }
    }
    return cached;
}

int meatrider_avx512_available(void) {
    static int cached = -1;
    if (cached < 0) {
        if (env_off("ANUBIS_NO_AVX512")) {
            cached = 0;
        } else {
            __builtin_cpu_init();
            cached = __builtin_cpu_supports("avx512f") ? 1 : 0;
        }
    }
    return cached;
}

int meatrider_batch_width(void) {
    if (meatrider_avx512_available()) return 16;
    if (meatrider_avx2_available()) return 8;
    return 0;
}

/* ------------------------------------------------------------------ */
/* One nonce                                                           */
/* ------------------------------------------------------------------ */

void meatrider_hash_shani(const meatrider_ctx *ctx, uint32_t nonce,
                          uint8_t out[32]) {
    uint8_t blk[64];
    uint32_t h[8];
    int i;

    meatrider_block1(ctx, nonce, blk);
    for (i = 0; i < 8; i++) h[i] = ctx->mid[i];
    meatrider_block_shani(h, blk);
    meatrider_block2(h, blk);
    meatrider_iv(h);
    meatrider_block_shani(h, blk);
    meatrider_finish(h, out);
}

/* ------------------------------------------------------------------ */
/* A lane group                                                        */
/* ------------------------------------------------------------------ */

/* Block 1 for each lane. Only four bytes differ between lanes (the nonce at
 * offset 12), so this is 12 fixed bytes, the nonce, and the constant padding. */
static void fill_block1(const meatrider_ctx *ctx, uint32_t base, uint32_t stride,
                        int lanes, uint8_t (*tails)[64]) {
    int lane, i;

    for (lane = 0; lane < lanes; lane++) {
        uint32_t n = base + (uint32_t)lane * stride;
        for (i = 0; i < 64; i++) tails[lane][i] = ctx->tail_block[i];
        tails[lane][12] = (uint8_t)n;
        tails[lane][13] = (uint8_t)(n >> 8);
        tails[lane][14] = (uint8_t)(n >> 16);
        tails[lane][15] = (uint8_t)(n >> 24);
    }
}

/* Block 2 for each lane from the first digest, which arrives as bytes and is
 * already the big-endian encoding block 2 wants. */
static void fill_block2(const uint8_t (*d1)[32], int lanes,
                        uint8_t (*tails)[64]) {
    int lane, i;

    for (lane = 0; lane < lanes; lane++) {
        for (i = 0; i < 32; i++) tails[lane][i] = d1[lane][i];
        tails[lane][32] = 0x80;
        for (i = 33; i < 62; i++) tails[lane][i] = 0;
        tails[lane][62] = 0x01;
        tails[lane][63] = 0x00;
    }
}

/* The display order is the byte reverse of the SHA-256 output, which is where
 * "Bitcoin" lives: a block explorer shows the digest backwards. */
static void reverse_lanes(const uint8_t (*in)[32], int lanes,
                          uint8_t (*out)[32]) {
    int lane, k;

    for (lane = 0; lane < lanes; lane++)
        for (k = 0; k < 32; k++)
            out[lane][k] = in[lane][31 - k];
}

void meatrider_hash8_avx2(const meatrider_ctx *ctx, uint32_t base,
                          uint32_t stride, uint8_t out[16][32]) {
    uint8_t b1[8][64], b2[8][64], d1[8][32];
    uint32_t iv[8];

    fill_block1(ctx, base, stride, 8, b1);
    meatrider_compress8_avx2(ctx->mid, (const uint8_t (*)[64])b1, d1);

    fill_block2(d1, 8, b2);
    meatrider_iv(iv);
    meatrider_compress8_avx2(iv, (const uint8_t (*)[64])b2, d1);

    reverse_lanes(d1, 8, out);
}

void meatrider_hash16_avx512(const meatrider_ctx *ctx, uint32_t base,
                             uint32_t stride, uint8_t out[16][32]) {
    uint8_t b1[16][64], b2[16][64], d1[16][32];
    uint32_t iv[8];

    fill_block1(ctx, base, stride, 16, b1);
    meatrider_compress16_avx512(ctx->mid, (const uint8_t (*)[64])b1, d1);

    fill_block2(d1, 16, b2);
    meatrider_iv(iv);
    meatrider_compress16_avx512(iv, (const uint8_t (*)[64])b2, d1);

    reverse_lanes(d1, 16, out);
}

int meatrider_hash_batch(const meatrider_ctx *ctx, uint32_t base,
                         uint32_t stride, int lanes, uint8_t out[16][32]) {
    if (lanes == 16 && meatrider_avx512_available()) {
        meatrider_hash16_avx512(ctx, base, stride, out);
        return 0;
    }
    if (lanes == 8 && meatrider_avx2_available()) {
        meatrider_hash8_avx2(ctx, base, stride, out);
        return 0;
    }
    return -1;
}

#endif /* MEATRIDER_HAVE_SIMD */
