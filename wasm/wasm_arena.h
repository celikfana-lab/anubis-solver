/* wasm_arena.h — the only allocator these modules need.
 *
 * argon2 and hashx allocate once, keep the memory and never free it, so a bump
 * allocator over a static region is enough and avoids pulling in a libc.
 */
#ifndef WASM_ARENA_H
#define WASM_ARENA_H
#include <stddef.h>
#include <stdint.h>

#ifndef ARENA_BYTES
#define ARENA_BYTES (21u << 20)      /* enough for argon2id's 19 MiB m_cost */
#endif

static uint8_t wasm_arena[ARENA_BYTES] __attribute__((aligned(16)));
static size_t wasm_arena_used;

void *malloc(size_t n) {
    size_t need = (n + 15u) & ~(size_t)15u;
    if (wasm_arena_used + need > ARENA_BYTES) return NULL;
    void *p = &wasm_arena[wasm_arena_used];
    wasm_arena_used += need;
    return p;
}
void free(void *p) { (void)p; }
void *calloc(size_t n, size_t m) {
    size_t total = n * m;
    uint8_t *p = malloc(total);
    if (p) for (size_t i = 0; i < total; i++) p[i] = 0;
    return p;
}
/* Argon2 allocates ~20 MiB per hash and keeps nothing between calls, so the arena
 * is reset before each one. Without this the second hash of a search finds the
 * arena exhausted and returns an error, which looks exactly like "solved nonce 0". */
static void arena_reset(void) { wasm_arena_used = 0; }

void *realloc(void *p, size_t n) {
    /* the bump allocator cannot grow in place: allocate and copy what we know */
    (void)p; return malloc(n);
}
#endif
