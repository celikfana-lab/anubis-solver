/* gen_hashx_vectors.c — stage vectors for beyond/tb/tb_hashx.v from the C
 * reference in src/hashx (LGPL-3.0, see THIRD_PARTY_NOTICES.md). Used only as
 * a test-vector generator, never linked into the library.
 *
 * Per case, 2058 words of 64 bits:
 *   [0..3]      keys k0..k3
 *   [4]         ninstr
 *   [5]         nonce
 *   [6..2053]   up to 512 instructions, (op, dst, src, imm32) per instruction
 *   [2054..2057] expected 32-byte tag as four little-endian 64-bit words
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashx.h"

#define CASE 2058

static void emit(const char *challenge_hex, unsigned long long nonce, FILE *f) {
    size_t n = strlen(challenge_hex) / 2;
    unsigned char *data = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++)
        sscanf(challenge_hex + 2 * i, "%2hhx", &data[i]);

    void *st = NULL;
    size_t st_size = 0;
    if (hashx_init(data, n, &st, &st_size) != 0) {
        fprintf(stderr, "hashx_init failed\n");
        exit(1);
    }

    unsigned char out[32];
    hashx_hash(st, st_size, nonce, out);

    uint64_t keys[4] = {0, 0, 0, 0};
    uint32_t prog[4 * 512];
    size_t ninstr = 0;
    memset(prog, 0, sizeof(prog));
    if (hashx_export(st, st_size, keys, prog, &ninstr) != 0) {
        fprintf(stderr, "hashx_export failed\n");
        exit(1);
    }

    for (int i = 0; i < 4; i++) fprintf(f, "%016llx\n", (unsigned long long)keys[i]);
    fprintf(f, "%016llx\n", (unsigned long long)ninstr);
    fprintf(f, "%016llx\n", nonce);
    for (int i = 0; i < 512; i++)
        for (int j = 0; j < 4; j++)
            fprintf(f, "%016llx\n", (unsigned long long)prog[4 * i + j]);
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int b = 0; b < 8; b++) w |= (uint64_t)out[8 * i + b] << (8 * b);
        fprintf(f, "%016llx\n", (unsigned long long)w);
    }

    fprintf(stderr, "case: |challenge|=%zu nonce=%llu instr=%zu\n", n,
            nonce, ninstr);
    hashx_free(st);
    free(data);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "vectors/hx_vectors.hex";
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return 1; }

    static const struct { const char *ch; unsigned long long nonce; } cases[] = {
        {"6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d", 0},
        {"6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d", 1},
        {"6a1f8c2e4d0b9a7f3c5e2d1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d", 0xDEADBEEFULL},
        {"0123456789abcdef", 42},
        {"00112233445566778899aabbccddeeff"
         "00112233445566778899aabbccddeeff"
         "00112233445566778899aabbccddeeff"
         "00112233445566778899aabbccddeeff", 7},
    };
    const int nc = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int i = 0; i < nc; i++) emit(cases[i].ch, cases[i].nonce, f);
    fclose(f);
    fprintf(stderr, "wrote %s: %d cases of %d words\n", path, nc, CASE);
    return 0;
}
