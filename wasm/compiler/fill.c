/* fill.c — Argon2id's fill_block in C, compiled to wasm.
 *
 * The same function as ../compiler/fill.rs and the two WAT kernels, so all of
 * them can be compared on identical work and checked against the same vectors.
 *
 *   clang --target=wasm32 -O3 -nostdlib -msimd128 \
 *         -Wl,--no-entry -Wl,--export=fill_block -Wl,--export-memory \
 *         -o fill_c_simd.wasm fill.c
 *
 * Drop -msimd128 for the scalar build. The inner round keeps its 16 words in a
 * local array indexed only by constants, so LLVM promotes them to registers.
 */
#include <stdint.h>

#define M32 0xFFFFFFFFULL

static inline uint64_t rotr64(uint64_t x, unsigned n) {
#if defined(__wasm__)
    return __builtin_rotateright64(x, n);
#else
    return (x >> n) | (x << (64 - n));
#endif
}

/* fBlaMka: x + y + 2*((x & 0xffffffff) * (y & 0xffffffff)), all mod 2^64 */
static inline uint64_t blamka(uint64_t x, uint64_t y) {
    return x + y + 2 * ((x & M32) * (y & M32));
}

#define G(a, b, c, d)                                                          \
    do {                                                                       \
        a = blamka(a, b);                                                      \
        d = rotr64(d ^ a, 32);                                                 \
        c = blamka(c, d);                                                      \
        b = rotr64(b ^ c, 24);                                                 \
        a = blamka(a, b);                                                      \
        d = rotr64(d ^ a, 16);                                                 \
        c = blamka(c, d);                                                      \
        b = rotr64(b ^ c, 63);                                                 \
    } while (0)

/* One BLAKE2 round over 16 words, exactly as BLAKE2_ROUND_NOMSG does it. */
static inline __attribute__((always_inline)) void round16(uint64_t v[16]) {
    G(v[0], v[4], v[8], v[12]);
    G(v[1], v[5], v[9], v[13]);
    G(v[2], v[6], v[10], v[14]);
    G(v[3], v[7], v[11], v[15]);
    G(v[0], v[5], v[10], v[15]);
    G(v[1], v[6], v[11], v[12]);
    G(v[2], v[7], v[8], v[13]);
    G(v[3], v[4], v[9], v[14]);
}

/* The eight row gathers, as constant tables so the loops unroll cleanly. */
static const unsigned char ROW[16] = {0, 1, 16, 17, 32, 33, 48, 49,
                                      64, 65, 80, 81, 96, 97, 112, 113};

void fill_block(uint64_t *dst, const uint64_t *prev, const uint64_t *ref,
                uint32_t with_xor) {
    uint64_t r[128], t[128];
    for (int i = 0; i < 128; i++) {
        const uint64_t x = ref[i] ^ prev[i];
        r[i] = x;
        t[i] = with_xor ? (x ^ dst[i]) : x;
    }

    for (int g = 0; g < 8; g++) round16(&r[16 * g]);

    for (int g = 0; g < 8; g++) {
        uint64_t v[16];
        for (int j = 0; j < 16; j++) v[j] = r[2 * g + ROW[j]];
        round16(v);
        for (int j = 0; j < 16; j++) r[2 * g + ROW[j]] = v[j];
    }

    for (int i = 0; i < 128; i++) dst[i] = t[i] ^ r[i];
}
