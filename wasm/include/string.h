/* string.h — the few routines hashx and argon2 use, freestanding for wasm32. */
#ifndef WASM_STRING_H
#define WASM_STRING_H
#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
char *strcpy(char *dst, const char *src);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strrchr(const char *s, int c);
char *strchr(const char *s, int c);
#endif
