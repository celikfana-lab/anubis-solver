/* stdlib.h — malloc/free come from wasm_arena.h; this only declares them. */
#ifndef WASM_STDLIB_H
#define WASM_STDLIB_H
#include <stddef.h>
void *malloc(size_t n);
void free(void *p);
void *calloc(size_t n, size_t m);
void *realloc(void *p, size_t n);
/* hashx checks the environment for its JIT switch; the wasm build has no env */
char *getenv(const char *name);
#endif
