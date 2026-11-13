/* hashx_pow.c — HashX in WebAssembly, ABI-compatible with Anubis's module.
 *
 * The HashX program is derived from the challenge, so unlike the SHA-256 kernel
 * this cannot be precompiled: it interprets the program our own engine generates
 * (src/hashx/hashx.c, LGPL-3.0), which is what the official module does too.
 *
 *   clang --target=wasm32 -O3 -nostdlib -Wl,--no-entry -Wl,--export-memory \
 *         -Wl,--export=data_ptr ... -o hashx_pow.wasm hashx_pow.c ../src/hashx/hashx.c
 */
#include <stddef.h>
#include <stdint.h>
#include "wasm_arena.h"
#include "hashx.h"

#define BUF_MAX 4096

static uint8_t buf[BUF_MAX];
static uint32_t buf_len;
static uint8_t result[32];

__attribute__((export_name("data_ptr"))) uint8_t *data_ptr(void) { return buf; }
__attribute__((export_name("set_data_length"))) void set_data_length(uint32_t n) {
    buf_len = n > BUF_MAX ? BUF_MAX : n;
}
__attribute__((export_name("result_hash_ptr"))) uint8_t *result_hash_ptr(void) { return result; }
__attribute__((export_name("result_hash_size"))) uint32_t result_hash_size(void) { return 32; }

static int zero_bits_ok(const uint8_t *h, uint32_t difficulty) {
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

__attribute__((export_name("anubis_work")))
uint32_t anubis_work(uint32_t difficulty, uint32_t nonce, uint32_t iterand) {
    if (iterand == 0) iterand = 1;
    void *state = NULL;
    size_t state_size = 0;
    if (hashx_init(buf, buf_len, &state, &state_size) != 0) return 0;
    for (;;) {
        hashx_hash(state, state_size, nonce, result);
        if (zero_bits_ok(result, difficulty)) return nonce;
        nonce += iterand;
    }
}
