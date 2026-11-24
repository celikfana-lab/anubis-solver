#ifndef FB_MEATRIDER_BACKEND_H
#define FB_MEATRIDER_BACKEND_H

/* The backend inventory of the `meatrider` tier.
 *
 * Every entry computes the same digest, on purpose: the tier's promise is that
 * a proof does not depend on which kernel produced it. The list exists so that
 * promise is checkable -- `anubis_meatrider_backend_digest()` asks one named
 * kernel for the digest of one nonce, and tools/meatrider_backends.py compares
 * all of them against the portable reference.
 */

#include "meatrider.h"

enum {
    MR_BACKEND_SCALAR = 0,   /* portable C, always present */
    MR_BACKEND_SHANI = 1,    /* Intel SHA extensions, one block at a time */
    MR_BACKEND_AVX2 = 2,     /* 8 nonces per pass */
    MR_BACKEND_AVX512 = 3,   /* 16 nonces per pass */
    MR_BACKEND_OPENCL = 4,
    MR_BACKEND_VULKAN = 5,
    MR_BACKEND_L0 = 6,       /* Intel Level Zero */
    MR_BACKEND_CUDA = 7,     /* CUDA C, or the generated PTX on the driver */
    MR_BACKEND_TPU = 8,
    MR_BACKEND_COUNT = 9
};

/* Name ("cpu", "shani", "avx2", "avx512", "opencl", "vulkan", "levelzero",
 * "cuda", "tpu"), or NULL for an id outside the list. */
const char *meatrider_backend_name(int id);

/* Id for a name (case-insensitive; "l0" is accepted for "levelzero"), or -1. */
int meatrider_backend_parse(const char *name);

/* 1 when the kernel is compiled in and this machine can run it now. */
int meatrider_backend_available(int id);

/* What anubis_solve_meatrider() will use: ANUBIS_MEATRIDER_BACKEND when it
 * names an available kernel, else the first available accelerator in the
 * dispatch order CUDA -> Level Zero -> Vulkan -> OpenCL, else the widest CPU
 * kernel. */
int meatrider_backend_active(void);

/* The digest of one nonce from one kernel, in display order. 0 on success,
 * -1 when the backend is unknown or unavailable. */
int meatrider_backend_digest(int id, const meatrider_ctx *ctx, uint32_t nonce,
                             uint8_t out[32]);

/* Search [start, start + count) on an accelerator. 0 = hit (nonce/digest
 * filled), 1 = the range ran out or the budget expired, -1 = not an
 * accelerator, unavailable, or the kernel failed (the caller falls back to the
 * CPU). Every hit is re-checked by the caller with meatrider_digest(), so a
 * kernel bug costs a wasted dispatch, not a wrong answer. */
int meatrider_backend_gpu_solve(int id, const meatrider_ctx *ctx,
                                uint32_t start, uint32_t count,
                                double budget_ms, uint32_t *nonce,
                                uint8_t digest[32]);

#endif /* FB_MEATRIDER_BACKEND_H */
