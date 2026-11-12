/*
 * anubis-solver.h — public C/C++ API for libanubis_solver.
 *
 * C:   #include <anubis-solver.h>
 * C++: #include <anubis-solver.h>   (functions are declared extern "C")
 *
 * Build:  cc  demo.c   -Iinclude -L. -lanubis_solver -Wl,-rpath,'$ORIGIN'
 *         c++ demo.cpp -Iinclude -L. -lanubis_solver -Wl,-rpath,'$ORIGIN'
 */

#ifndef ANUBIS_SOLVER_H
#define ANUBIS_SOLVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes. */
#define ANUBIS_OK 0
#define ANUBIS_ERR_ARG 1
#define ANUBIS_ERR_UNSOLVED 2
#define ANUBIS_ERR_INTERNAL 3

#if defined(_WIN32) && defined(ANUBIS_BUILD_SHARED)
#  define ANUBIS_API __declspec(dllexport)
#elif defined(_WIN32)
#  define ANUBIS_API __declspec(dllimport)
#else
#  define ANUBIS_API
#endif

/* ------------------------------------------------------------------ *
 * Introspection
 * ------------------------------------------------------------------ */

/* Library version, e.g. "1.0.0". */
ANUBIS_API const char *anubis_solver_version(void);

/* Name of the active GPU backend (e.g. "CUDA: Tesla T4 x2"), or NULL. */
ANUBIS_API const char *anubis_gpu_info(void);

/* Sensible default worker count (physical cores). */
ANUBIS_API int anubis_default_threads(void);

/* Human-readable CPU affinity, e.g. "P-cores (0,2,4,...)" or "off". */
ANUBIS_API const char *anubis_cpu_affinity_info(void);

/* SHA-256 batch width: 16 (AVX-512), 8 (AVX2), 0 (scalar). */
ANUBIS_API int anubis_batch_width(void);

/* ------------------------------------------------------------------ *
 * SHA-256 helpers
 * ------------------------------------------------------------------ */

/* Hex SHA-256 of `data`; `out_hex` must hold 65 bytes. */
ANUBIS_API int anubis_sha256_hex(const char *data, size_t len, char *out_hex);

/* SHA-256 midstate after `len` bytes (len must be a multiple of 64). */
ANUBIS_API int anubis_sha256_midstate(const char *data, size_t len,
                                      uint32_t out[8]);

/* ------------------------------------------------------------------ *
 * Solving
 *
 * Each returns ANUBIS_OK on a hit, ANUBIS_ERR_UNSOLVED when max_nonce or
 * budget_ms is exhausted, or another ANUBIS_* error code.
 *
 * threads:   0 = anubis_default_threads()
 * max_nonce: 0 = no nonce limit (nibbles family only)
 * budget_ms: <= 0 = no time limit
 * out_hex:   65-byte buffer, receives the hash as lowercase hex
 * out_ms:    optional, receives the elapsed time
 * ------------------------------------------------------------------ */

/* `fast` / `slow` (leading zero nibbles). */
ANUBIS_API int anubis_solve_nibbles(const char *challenge, int difficulty,
                                    int threads, int64_t max_nonce,
                                    double budget_ms, uint64_t *out_nonce,
                                    char *out_hex, double *out_ms);

/* `sha256` / `wasm-sha256` (leading zero bits). */
ANUBIS_API int anubis_solve_bits(const char *challenge_hex, int difficulty,
                                 int threads, double budget_ms,
                                 uint32_t *out_nonce, char *out_hex,
                                 double *out_ms);

/* `argon2id` (leading zero bits, Argon2id v1.3). */
ANUBIS_API int anubis_solve_argon2id(const char *challenge_hex, int difficulty,
                                     int threads, double budget_ms,
                                     uint32_t *out_nonce, char *out_hex,
                                     double *out_ms);

/* `hashx` (leading zero bits, HashX program). */
ANUBIS_API int anubis_solve_hashx(const char *challenge_hex, int difficulty,
                                  int threads, double budget_ms,
                                  uint32_t *out_nonce, char *out_hex,
                                  double *out_ms);

/* ------------------------------------------------------------------ *
 * Verification (re-check a nonce; returns ANUBIS_OK when valid)
 * ------------------------------------------------------------------ */

ANUBIS_API int anubis_verify_nibbles(const char *challenge, uint64_t nonce,
                                     int difficulty, char *out_hex);
ANUBIS_API int anubis_verify_bits(const char *challenge_hex, uint32_t nonce,
                                  int difficulty, char *out_hex);
ANUBIS_API int anubis_verify_argon2id(const char *challenge_hex, uint32_t nonce,
                                      int difficulty, char *out_hex);
ANUBIS_API int anubis_verify_hashx(const char *challenge_hex, uint32_t nonce,
                                   int difficulty, char *out_hex);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ANUBIS_SOLVER_H */
