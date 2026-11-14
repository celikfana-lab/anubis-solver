/*
 * xe-hashx-export.c - dump a HashX program and its digests for the Xe listing.
 *
 * The Xe generator needs the same program the C reference runs, and it must
 * compare against the same digests. Both come from here, so the assembly is
 * checked against the reference implementation rather than against a second
 * Python reimplementation of the generator (which is how a port drifts).
 *
 *   cc -O2 -o /tmp/hxe tools/xe-hashx-export.c src/hashx/hashx.c -Isrc/hashx
 *   /tmp/hxe 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 8
 *
 * Prints:
 *   keys <k0> <k1> <k2> <k3>
 *   count <n>
 *   prog <op> <dst> <src> <imm>     (n lines)
 *   nonce <i> <64 hex chars>        (one line per nonce)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashx.h"

static int unhex(const char *in, unsigned char *out, size_t cap) {
    size_t n = strlen(in) / 2;
    if (n > cap) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(in + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return (int)n;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s CHALLENGE_HEX [NONCES]\n", argv[0]);
        return 2;
    }
    unsigned char data[512];
    int dlen = unhex(argv[1], data, sizeof data);
    if (dlen <= 0) {
        fprintf(stderr, "bad hex\n");
        return 2;
    }
    int nonces = argc > 2 ? atoi(argv[2]) : 8;

    void *state = NULL;
    size_t state_size = 0;
    if (hashx_init(data, (size_t)dlen, &state, &state_size) != 0) {
        fprintf(stderr, "hashx_init failed\n");
        return 1;
    }

    uint64_t keys[4];
    static uint32_t prog[4 * 512];
    size_t count = 0;
    if (hashx_export(state, state_size, keys, prog, &count) != 0) {
        fprintf(stderr, "hashx_export failed\n");
        return 1;
    }

    printf("keys %llu %llu %llu %llu\n", (unsigned long long)keys[0],
           (unsigned long long)keys[1], (unsigned long long)keys[2],
           (unsigned long long)keys[3]);
    printf("count %zu\n", count);
    for (size_t i = 0; i < count; i++)
        printf("prog %u %u %u %u\n", prog[4 * i], prog[4 * i + 1], prog[4 * i + 2],
               prog[4 * i + 3]);

    for (int i = 0; i < nonces; i++) {
        unsigned char out[32];
        hashx_hash(state, state_size, (unsigned long long)i, out);
        printf("nonce %d ", i);
        for (int j = 0; j < 32; j++) printf("%02x", out[j]);
        printf("\n");
    }

    hashx_free(state);
    return 0;
}
