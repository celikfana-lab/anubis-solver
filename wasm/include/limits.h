/* limits.h — freestanding wasm32 has no target limits header to include. */
#ifndef WASM_LIMITS_H
#define WASM_LIMITS_H
#define CHAR_BIT 8
#define INT_MAX 2147483647
#define INT_MIN (-2147483647 - 1)
#define UINT_MAX 4294967295u
#define LONG_MAX 2147483647L
#define ULONG_MAX 4294967295UL
#define LLONG_MAX 9223372036854775807LL
#define ULLONG_MAX 18446744073709551615ULL
#endif
