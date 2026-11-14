/*
 * xe-hashx-stages.c - dump the HashX intermediate register files.
 *
 * hashx.c keeps its generator and interpreter static, and that is where the
 * interesting values are. Including the translation unit gives this helper
 * access to them, which is the point: the Xe listing is compared stage by
 * stage against the reference rather than only at the final digest (where a
 * single wrong bit tells you nothing about which stage produced it).
 *
 *   cc -O2 -o /tmp/hxs tools/xe-hashx-stages.c -Isrc/hashx -Isrc
 *   /tmp/hxs 0011...eeff 2
 *
 * Prints, for nonce 0..N-1:
 *   expand <nonce> <r0..r7 as 16 hex digits each>
 *   post   <nonce> <r0..r7>
 *   digest <nonce> <64 hex>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/hashx/hashx.c"

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

static void dump(const char *tag, unsigned long long nonce, const uint64_t r[8]) {
    printf("%s %llu", tag, nonce);
    for (int i = 0; i < 8; i++) printf(" %016llx", (unsigned long long)r[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s CHALLENGE_HEX [NONCES]\n", argv[0]);
        return 2;
    }
    unsigned char data[512];
    int dlen = unhex(argv[1], data, sizeof data);
    if (dlen <= 0) return 2;
    int nonces = argc > 2 ? atoi(argv[2]) : 2;

    void *state = NULL;
    size_t state_size = 0;
    if (hashx_init(data, (size_t)dlen, &state, &state_size) != 0) return 1;
    const hashx_state *st = (const hashx_state *)state;
    (void)state_size;

    for (int n = 0; n < nonces; n++) {
        uint64_t r[8];
        hashx_siphash24_ctr_state512(&st->keys, (uint64_t)n, r);
        dump("expand", (unsigned long long)n, r);
        hashx_program_execute(&st->program, r);
        dump("post", (unsigned long long)n, r);

        unsigned char out[32];
        hashx_hash(state, state_size, (unsigned long long)n, out);
        printf("digest %d ", n);
        for (int j = 0; j < 32; j++) printf("%02x", out[j]);
        printf("\n");
    }
    hashx_free(state);
    return 0;
}
