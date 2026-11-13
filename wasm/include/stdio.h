/* stdio.h — hashx's tracer is compiled in but never runs in the browser, so
 * printf goes nowhere. Keeping the declarations lets the same source build. */
#ifndef WASM_STDIO_H
#define WASM_STDIO_H
#include <stddef.h>
typedef struct wasm_FILE FILE;
int printf(const char *fmt, ...);
int snprintf(char *buf, size_t n, const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
int fprintf(FILE *f, const char *fmt, ...);
#endif
