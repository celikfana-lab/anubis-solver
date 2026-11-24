#ifndef FB_MEATRIDER_SIMD_H
#define FB_MEATRIDER_SIMD_H

/* The x86-64 backends of the `meatrider` tier.
 *
 * Same split as the `sha256` tier: src/meatrider/meatrider.c is the portable
 * reference and is the only file compiled into wasm, while the kernels that
 * need assembly live here and are linked into libanubis_solver.so only.
 *
 * One hash is two compressions, so the vector paths call their compression
 * kernel twice: once with the header's midstate and the lanes' block 1, once
 * with the SHA-256 IV and block 2 built from the lanes' first digests. The
 * results come back in Bitcoin display order, ready for meatrider_meets().
 */

#include "meatrider.h"

#if defined(__x86_64__) && !defined(_WIN32) && \
    (defined(__GNUC__) || defined(__clang__)) && !defined(MEATRIDER_NO_SIMD)
#define MEATRIDER_HAVE_SIMD 1
#endif

#ifdef MEATRIDER_HAVE_SIMD

/* 1 when this CPU can run the kernel right now. Each honours a kill switch
 * (ANUBIS_NO_SHANI, ANUBIS_NO_AVX2, ANUBIS_NO_AVX512) so a benchmark can pin
 * a row to a kernel. */
int meatrider_shani_available(void);
int meatrider_avx2_available(void);
int meatrider_avx512_available(void);

/* One nonce, two SHA-NI compressions (~80 cycles each instead of ~940). */
void meatrider_hash_shani(const meatrider_ctx *ctx, uint32_t nonce,
                          uint8_t out[32]);

/* Eight (AVX2) or sixteen (AVX-512) nonces at once: lane k hashes
 * base + k * stride, which is how the search loop interleaves threads. `out`
 * is display order per lane, so the caller's leading-zero-bits test applies
 * unchanged. */
void meatrider_hash8_avx2(const meatrider_ctx *ctx, uint32_t base,
                          uint32_t stride, uint8_t out[16][32]);
void meatrider_hash16_avx512(const meatrider_ctx *ctx, uint32_t base,
                             uint32_t stride, uint8_t out[16][32]);

/* The widest batch this CPU can run: 16, 8, or 0 when neither is available. */
int meatrider_batch_width(void);

/* Hash `lanes` (8 or 16) nonces with the widest available kernel. Returns 0,
 * or -1 when no batch kernel is available at all. */
int meatrider_hash_batch(const meatrider_ctx *ctx, uint32_t base,
                         uint32_t stride, int lanes, uint8_t out[16][32]);

#else /* portable build: no assembly, no SIMD */

#define meatrider_shani_available() 0
#define meatrider_avx2_available() 0
#define meatrider_avx512_available() 0
#define meatrider_batch_width() 0
#define meatrider_hash_batch(ctx, base, stride, lanes, out) (-1)

#endif /* MEATRIDER_HAVE_SIMD */

#endif /* FB_MEATRIDER_SIMD_H */
