/* meatrider_pow.c -- the `meatrider` tier as a wasm kernel.
 *
 * Same ABI as the modules Anubis ships, so the same JavaScript can drive it:
 *
 *   data_ptr() -> u32            write the 32-byte randomData here
 *   set_data_length(u32)         must be 32 for this tier
 *   result_hash_ptr() -> u32     the 32-byte digest of the winning nonce
 *   result_hash_size() -> u32    32
 *   anubis_work(difficulty, nonce, iterand) -> u32
 *                                scans nonce, nonce+iterand, ... until the
 *                                digest has `difficulty` leading zero bits
 *   anubis_work_limited(difficulty, nonce, iterand, limit) -> i32
 *                                the same, but gives up after `limit` tries and
 *                                returns -1, so a page can keep a progress bar
 *                                moving and stay interruptible
 *
 * The hash itself is src/meatrider/meatrider.c -- the same translation unit the
 * native library compiles -- so the browser and the server cannot disagree
 * about the header. That file uses no libc, which is what makes this build a
 * single clang invocation.
 *
 *   clang --target=wasm32 -O3 -nostdlib -Wl,--no-entry -I../src/meatrider \
 *         -Wl,--export-memory -Wl,--export=data_ptr \
 *         -Wl,--export=set_data_length -Wl,--export=result_hash_ptr \
 *         -Wl,--export=result_hash_size -Wl,--export=anubis_work \
 *         -Wl,--export=anubis_work_limited \
 *         -o meatrider_pow.wasm meatrider_pow.c ../src/meatrider/meatrider.c
 */
#include <stdint.h>

#include "meatrider.h"

static uint8_t buf[64];
static uint32_t buf_len;
static uint8_t result[32];

static meatrider_ctx ctx;
static uint32_t ctx_bits;      /* the difficulty the context was built for */
static uint8_t ctx_rd[32];     /* ... and the challenge, so a reused module
                                * with a fresh challenge rebuilds */
static int ctx_ready;

uint8_t *data_ptr(void) { return buf; }
void set_data_length(uint32_t n) { buf_len = n > sizeof buf ? (uint32_t)sizeof buf : n; }
uint8_t *result_hash_ptr(void) { return result; }
uint32_t result_hash_size(void) { return 32; }

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
 * so it is cached across the windows a page asks for. */
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

int anubis_work_limited(uint32_t difficulty, uint32_t nonce, uint32_t iterand,
                        uint32_t limit) {
    if (iterand == 0) iterand = 1;
    if (prepare(difficulty) != 0) return -1;
    for (uint32_t i = 0; i < limit; i++) {
        meatrider_hash(&ctx, nonce, result);
        if (has_enough_zero_bits(result, difficulty)) return (int)nonce;
        nonce += iterand;
    }
    return -1;
}

int anubis_work(uint32_t difficulty, uint32_t nonce, uint32_t iterand) {
    if (iterand == 0) iterand = 1;
    if (prepare(difficulty) != 0) return -1;
    for (;;) {
        meatrider_hash(&ctx, nonce, result);
        if (has_enough_zero_bits(result, difficulty)) return (int)nonce;
        nonce += iterand;
    }
}
