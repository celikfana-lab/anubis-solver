/* ref_fill_vectors.c — authoritative fill_block vectors from the vendored Argon2
 * reference implementation, so the WAT port has something to be checked against
 * that is not itself a port.
 *
 *   cc -O1 -pthread -I../third_party/argon2 -I../third_party/argon2/blake2 \
 *      -o /tmp/fillref ref_fill_vectors.c \
 *      ../third_party/argon2/blake2/blake2b.c ../third_party/argon2/thread.c
 *   /tmp/fillref > fill_vectors.txt
 *
 * Output, per trial: "<trial> <with_xor>" then 128 result words, then the 128
 * prev words (8 per line) and the 128 ref words. Three trials: overwrite, then
 * two xor-into. Inputs come from a fixed LCG so the file is reproducible.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../third_party/argon2/core.c"
#include "../third_party/argon2/ref.c"

static uint64_t s = 0x243F6A8885A308D3ULL;
static uint64_t next64(void) { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }

int main(void) {
    block prev, ref, next;
    for (int trial = 0; trial < 3; trial++) {
        int with_xor = trial > 0;
        for (int i = 0; i < 128; i++) {
            prev.v[i] = next64();
            ref.v[i]  = next64();
            next.v[i] = with_xor ? next64() : 0;
        }
        /* echo every input so the checker does not have to guess at them, then
         * the result; all words space separated, 8 per line */
        printf("trial %d xor %d\n", trial, with_xor);
        const char *names[3] = {"prev", "ref", "next"};
        const block *blks[3] = {&prev, &ref, &next};
        for (int b = 0; b < 3; b++) {
            printf("%s\n", names[b]);
            for (int i = 0; i < 128; i++) {
                printf("%016llx", (unsigned long long)blks[b]->v[i]);
                printf(i % 8 == 7 ? "\n" : " ");
            }
        }
        fill_block(&prev, &ref, &next, with_xor);
        printf("result\n");
        for (int i = 0; i < 128; i++) {
            printf("%016llx", (unsigned long long)next.v[i]);
            printf(i % 8 == 7 ? "\n" : " ");
        }
    }
    return 0;
}
