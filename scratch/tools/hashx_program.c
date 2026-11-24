#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Dump a HashX program and its reference digests, for the Scratch port.
 *
 * HashX is a RandomX-style VM: the challenge seeds a generator that emits a
 * program of up to 512 instructions over eight 64-bit registers, and a hash is
 * "initialise the registers from the nonce, run the program, sipmix, output".
 * The *interpreter* is 11 integer opcodes and no memory, so it can be written in
 * blocks; the generator cannot (RandomX's superscalar scheduler is ~700 lines of
 * intricate constraint code), so this tool extracts the program for a challenge:
 *
 *   cc -O2 -I src/hashx -o build/hashx_program scratch/tools/hashx_program.c \
 *      src/hashx/hashx.c
 *   ./build/hashx_program <challenge-hex> 4
 *
 * Output: the key vector, one line per instruction (opcode, dst, src, imm32), and
 * the first N digests as the C library computes them -- the ground truth any
 * blocks implementation has to match.
 */
#include "hashx.h"

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <challenge-hex> [n]\n", argv[0]); return 2; }
    size_t hexlen = strlen(argv[1]), dlen = hexlen / 2;
    unsigned char *data = malloc(dlen);
    for (size_t i = 0; i < dlen; i++)
        data[i] = (unsigned char)((hexval(argv[1][2 * i]) << 4) | hexval(argv[1][2 * i + 1]));
    int n = argc > 2 ? atoi(argv[2]) : 4;

    void *state = NULL;
    size_t ssize = 0;
    if (hashx_init(data, dlen, &state, &ssize) != 0) { fprintf(stderr, "init failed\n"); return 1; }

    uint64_t keys[4];
    static uint32_t prog[4 * 512];
    size_t count = 0;
    if (hashx_export(state, ssize, keys, prog, &count) != 0) { fprintf(stderr, "export failed\n"); return 1; }

    printf("count %zu\n", count);
    printf("keys %016llx %016llx %016llx %016llx\n",
           (unsigned long long)keys[0], (unsigned long long)keys[1],
           (unsigned long long)keys[2], (unsigned long long)keys[3]);
    for (size_t i = 0; i < count; i++)
        printf("i %zu %u %u %u %u\n", i, prog[4*i], prog[4*i+1], prog[4*i+2], prog[4*i+3]);
    for (int k = 0; k < n; k++) {
        unsigned char out[32];
        hashx_hash(state, ssize, (unsigned long long)k, out);
        printf("h %d ", k);
        for (int b = 0; b < 32; b++) printf("%02x", out[b]);
        printf("\n");
    }
    hashx_free(state);
    return 0;
}
