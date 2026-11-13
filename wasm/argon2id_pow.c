/* argon2id_pow.c — Argon2id in WebAssembly, ABI-compatible with Anubis's module.
 *
 * Anubis's Rust build calls `Argon2::default()`: Argon2id v19, m_cost 19456 KiB,
 * t_cost 2, p_cost 1, 32-byte output, with the challenge bytes as the *password*
 * and the nonce as the 8-byte salt (little- or big-endian depending on the last
 * challenge byte). This calls the vendored reference implementation with exactly
 * those parameters, so the two must agree byte for byte.
 *
 *   clang --target=wasm32 -O3 -DARGON2_NO_THREADS -nostdlib -Wl,--no-entry \
 *         -Wl,--export-memory -Wl,--export=data_ptr ... -o argon2id_pow.wasm \
 *         argon2id_pow.c ../third_party/argon2/{argon2.c,core.c,ref.c,
 *         blake2/blake2b.c,encoding.c}
 */
#include <stddef.h>
#include <stdint.h>
#include "wasm_arena.h"
#include "argon2.h"

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
    const int le = buf_len > 0 && buf[buf_len - 1] >= 0x80;
    for (;;) {
        uint8_t salt[8];
        uint32_t n = nonce;
        if (le) {
            for (int i = 0; i < 4; i++) { salt[i] = (uint8_t)(n >> (8 * i)); salt[4 + i] = 0; }
        } else {
            for (int i = 0; i < 4; i++) { salt[7 - i] = (uint8_t)(n >> (8 * i)); salt[3 - i] = 0; }
        }
        arena_reset();
        int rc = argon2id_hash_raw(2, 19456, 1, buf, buf_len, salt, sizeof salt,
                                   result, sizeof result);
        if (rc != ARGON2_OK) return 0;
        if (zero_bits_ok(result, difficulty)) return nonce;
        nonce += iterand;
    }
}
