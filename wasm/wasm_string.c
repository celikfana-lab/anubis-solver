/* The string routines LLVM may emit calls to, and the ones hashx/argon2 call. */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst; const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dst;
}
void *memmove(void *dst, const void *src, size_t n) {
    uint8_t *d = dst; const uint8_t *s = src;
    if (d < s) { while (n--) *d++ = *s++; }
    else { d += n; s += n; while (n--) *--d = *--s; }
    return dst;
}
void *memset(void *dst, int c, size_t n) {
    uint8_t *d = dst;
    while (n--) *d++ = (uint8_t)c;
    return dst;
}
int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    while (n--) { if (*x != *y) return *x - *y; x++; y++; }
    return 0;
}
size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
char *strcpy(char *dst, const char *src) { char *d = dst; while ((*d++ = *src++)) {} return dst; }
int strncmp(const char *a, const char *b, size_t n) {
    while (n--) { if (*a != *b) return (unsigned char)*a - (unsigned char)*b;
                  if (!*a) break; a++; b++; }
    return 0;
}
char *strchr(const char *s, int c) {
    for (;; s++) { if (*s == (char)c) return (char *)s; if (!*s) return NULL; }
}
char *strrchr(const char *s, int c) {
    const char *last = NULL;
    for (;; s++) { if (*s == (char)c) last = s; if (!*s) return (char *)last; }
}
int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

/* the tracer in hashx.c references printf even when it is switched off */
int printf(const char *fmt, ...) { (void)fmt; return 0; }
int snprintf(char *buf, size_t n, const char *fmt, ...) {
    (void)fmt; if (n) buf[0] = 0; return 0;
}
int fprintf(void *f, const char *fmt, ...) { (void)f; (void)fmt; return 0; }
/* only argon2's debug encoder string reaches this, never the solver path */
int sprintf(char *buf, const char *fmt, ...) { (void)fmt; if (buf) buf[0] = 0; return 0; }
char *getenv(const char *name) { (void)name; return NULL; }
