/* meatrider_backend.c -- what can hash a Bitcoin header on this machine.
 *
 * The inventory itself is boring; the point is that it is reachable one kernel
 * at a time. anubis_meatrider_backend_digest() asks a named backend for the
 * digest of one nonce, so "every kernel agrees" is a test rather than a claim
 * (tools/meatrider_backends.py), and ANUBIS_MEATRIDER_BACKEND pins the search
 * to one kernel for benchmarking or for reproducing a bug report.
 */

#include "meatrider_backend.h"

#include <stdlib.h>
#include <string.h>

#include "meatrider_simd.h"

/* The accelerators. Each one lives next to its tier's other kernels and
 * reports 0/-1 from _available, 0/1/-1 from _solve (hit / exhausted /
 * failure, as the repo's backends do). */
#if defined(ANUBIS_MEATRIDER_OPENCL)
int anubis_opencl_meatrider_available(void);
int anubis_opencl_meatrider_solve(const meatrider_ctx *ctx, uint32_t start,
                                  uint32_t count, double budget_ms,
                                  uint32_t *nonce, uint8_t digest[32]);
#endif
#if defined(ANUBIS_MEATRIDER_VULKAN)
int anubis_vulkan_meatrider_available(void);
int anubis_vulkan_meatrider_solve(const meatrider_ctx *ctx, uint32_t start,
                                  uint32_t count, double budget_ms,
                                  uint32_t *nonce, uint8_t digest[32]);
#endif
#if defined(ANUBIS_MEATRIDER_L0)
int anubis_l0_meatrider_available(void);
int anubis_l0_meatrider_solve(const meatrider_ctx *ctx, uint32_t start,
                              uint32_t count, double budget_ms,
                              uint32_t *nonce, uint8_t digest[32]);
#endif
/* The generated PTX is always compiled in: it needs only libcuda.so.1, which
 * the loader dlopen()s, so it works on a box with a driver and no toolkit. */
int anubis_meatrider_ptx_available(void);
const char *anubis_meatrider_ptx_info(void);
int anubis_meatrider_ptx_solve(const uint32_t mid[8], const uint32_t tail[3],
                               int difficulty, uint32_t start, uint32_t count,
                               double budget_ms, uint32_t *nonce,
                               uint32_t hashes[8], int *dispatches);

#if defined(ANUBIS_MEATRIDER_CUDA)
int anubis_cuda_meatrider_available(void);
int anubis_cuda_meatrider_solve(const meatrider_ctx *ctx, uint32_t start,
                                uint32_t count, double budget_ms,
                                uint32_t *nonce, uint8_t digest[32]);
#endif
#if defined(ANUBIS_MEATRIDER_TPU)
int anubis_tpu_meatrider_available(void);
int anubis_tpu_meatrider_solve(const meatrider_ctx *ctx, uint32_t start,
                               uint32_t count, double budget_ms,
                               uint32_t *nonce, uint8_t digest[32]);
#endif

static const char *const NAMES[MR_BACKEND_COUNT] = {
    "cpu", "shani", "avx2", "avx512", "opencl", "vulkan", "levelzero", "cuda",
    "tpu",
};

const char *meatrider_backend_name(int id) {
    if (id < 0 || id >= MR_BACKEND_COUNT) return NULL;
    return NAMES[id];
}

static int name_eq(const char *a, const char *b) {
    for (;; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        if (ca == '\0') return 1;
    }
}

int meatrider_backend_parse(const char *name) {
    int i;

    if (name == NULL) return -1;
    for (i = 0; i < MR_BACKEND_COUNT; i++)
        if (name_eq(name, NAMES[i])) return i;
    if (name_eq(name, "l0")) return MR_BACKEND_L0;
    if (name_eq(name, "scalar")) return MR_BACKEND_SCALAR;
    if (name_eq(name, "level-zero")) return MR_BACKEND_L0;
    if (name_eq(name, "ptx")) return MR_BACKEND_CUDA;
    return -1;
}

int meatrider_backend_available(int id) {
    switch (id) {
    case MR_BACKEND_SCALAR:
        return 1;
    case MR_BACKEND_SHANI:
        return meatrider_shani_available();
    case MR_BACKEND_AVX2:
        return meatrider_avx2_available();
    case MR_BACKEND_AVX512:
        return meatrider_avx512_available();
#if defined(ANUBIS_MEATRIDER_OPENCL)
    case MR_BACKEND_OPENCL:
        return anubis_opencl_meatrider_available();
#endif
#if defined(ANUBIS_MEATRIDER_VULKAN)
    case MR_BACKEND_VULKAN:
        return anubis_vulkan_meatrider_available();
#endif
#if defined(ANUBIS_MEATRIDER_L0)
    case MR_BACKEND_L0:
        return anubis_l0_meatrider_available();
#endif
    case MR_BACKEND_CUDA:
#if defined(ANUBIS_MEATRIDER_CUDA)
        return anubis_cuda_meatrider_available() || anubis_meatrider_ptx_available();
#else
        /* no nvcc at build time, but the driver can still JIT the PTX */
        return anubis_meatrider_ptx_available();
#endif
#if defined(ANUBIS_MEATRIDER_TPU)
    case MR_BACKEND_TPU:
        return anubis_tpu_meatrider_available();
#endif
    default:
        return 0;
    }
}

int meatrider_backend_active(void) {
    int id;
    const char *want = getenv("ANUBIS_MEATRIDER_BACKEND");

    if (want != NULL && want[0] != '\0') {
        id = meatrider_backend_parse(want);
        if (id >= 0 && meatrider_backend_available(id)) return id;
        /* An unavailable pin is not an error here: the caller falls back to
         * the best CPU kernel, and reports the mismatch itself. */
    }
    /* Dispatch order, the same one the rest of the library uses. */
    if (meatrider_backend_available(MR_BACKEND_CUDA)) return MR_BACKEND_CUDA;
    if (meatrider_backend_available(MR_BACKEND_L0)) return MR_BACKEND_L0;
    if (meatrider_backend_available(MR_BACKEND_VULKAN)) return MR_BACKEND_VULKAN;
    if (meatrider_backend_available(MR_BACKEND_OPENCL)) return MR_BACKEND_OPENCL;
    if (meatrider_backend_available(MR_BACKEND_AVX512)) return MR_BACKEND_AVX512;
    if (meatrider_backend_available(MR_BACKEND_AVX2)) return MR_BACKEND_AVX2;
    if (meatrider_backend_available(MR_BACKEND_SHANI)) return MR_BACKEND_SHANI;
    return MR_BACKEND_SCALAR;
}

int meatrider_backend_digest(int id, const meatrider_ctx *ctx, uint32_t nonce,
                             uint8_t out[32]) {
    if (ctx == NULL || out == NULL) return -1;

    switch (id) {
    case MR_BACKEND_SCALAR:
        meatrider_hash(ctx, nonce, out);
        return 0;
    case MR_BACKEND_SHANI:
        if (!meatrider_shani_available()) return -1;
        meatrider_hash_shani(ctx, nonce, out);
        return 0;
    case MR_BACKEND_AVX2:
        if (!meatrider_avx2_available()) return -1;
        {
            uint8_t lanes[16][32];
            meatrider_hash8_avx2(ctx, nonce, 1, lanes);
            memcpy(out, lanes[0], 32);
        }
        return 0;
    case MR_BACKEND_AVX512:
        if (!meatrider_avx512_available()) return -1;
        {
            uint8_t lanes[16][32];
            meatrider_hash16_avx512(ctx, nonce, 1, lanes);
            memcpy(out, lanes[0], 32);
        }
        return 0;
    default:
        /* The accelerators hash to a hit buffer, not a digest buffer, so their
         * per-nonce digest is asked for through the search itself; see
         * anubis_meatrider_backend_digest() in the public header. */
        return -1;
    }
}

int meatrider_backend_gpu_solve(int id, const meatrider_ctx *ctx,
                                uint32_t start, uint32_t count,
                                double budget_ms, uint32_t *nonce,
                                uint8_t digest[32]) {
    (void)ctx;
    (void)start;
    (void)count;
    (void)budget_ms;
    (void)nonce;
    (void)digest;
    switch (id) {
    case MR_BACKEND_CUDA: {
        /* ANUBIS_MEATRIDER_PTX=1 asks for the generated PTX instead of the .cu
         * kernel. On a T4 the PTX path measured 994.7 MHash/s against the
         * kernel's 785.8 (SPEED.md), because the whole schedule is unrolled in
         * registers; the .cu stays the default because it needs no data file. */
        const char *want_ptx = getenv("ANUBIS_MEATRIDER_PTX");
        int prefer_ptx = want_ptx != NULL && want_ptx[0] != '\0' &&
                         want_ptx[0] != '0';
#if defined(ANUBIS_MEATRIDER_CUDA)
        if (!prefer_ptx && anubis_cuda_meatrider_available()) {
            int rc = anubis_cuda_meatrider_solve(ctx, start, count, budget_ms,
                                                 nonce, digest);
            if (rc >= 0) {
                return rc;
            }
        }
#endif
        if (!anubis_meatrider_ptx_available()) {
            return -1;
        }
        {
            uint32_t tail[3];
            uint32_t hashes[8];
            int i;
            for (i = 0; i < 3; i++) {
                tail[i] = (uint32_t)ctx->tail[4 * i] |
                          ((uint32_t)ctx->tail[4 * i + 1] << 8) |
                          ((uint32_t)ctx->tail[4 * i + 2] << 16) |
                          ((uint32_t)ctx->tail[4 * i + 3] << 24);
            }
            {
                int rc = anubis_meatrider_ptx_solve(ctx->mid, tail, ctx->difficulty,
                                                    start, count, budget_ms, nonce,
                                                    hashes, NULL);
                if (rc != 0) {
                    return rc;
                }
            }
            for (i = 0; i < 8; i++) {
                digest[4 * i + 0] = (uint8_t)(hashes[i] >> 24);
                digest[4 * i + 1] = (uint8_t)(hashes[i] >> 16);
                digest[4 * i + 2] = (uint8_t)(hashes[i] >> 8);
                digest[4 * i + 3] = (uint8_t)hashes[i];
            }
        }
        return 0;
    }
#if defined(ANUBIS_MEATRIDER_L0)
    case MR_BACKEND_L0:
        return anubis_l0_meatrider_solve(ctx, start, count, budget_ms, nonce,
                                         digest);
#endif
#if defined(ANUBIS_MEATRIDER_VULKAN)
    case MR_BACKEND_VULKAN:
        return anubis_vulkan_meatrider_solve(ctx, start, count, budget_ms,
                                             nonce, digest);
#endif
#if defined(ANUBIS_MEATRIDER_OPENCL)
    case MR_BACKEND_OPENCL:
        return anubis_opencl_meatrider_solve(ctx, start, count, budget_ms,
                                             nonce, digest);
#endif
#if defined(ANUBIS_MEATRIDER_TPU)
    case MR_BACKEND_TPU:
        return anubis_tpu_meatrider_solve(ctx, start, count, budget_ms, nonce,
                                          digest);
#endif
    default:
        return -1;
    }
}
