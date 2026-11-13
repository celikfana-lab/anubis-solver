// anubis.inc — calling libanubis_solver from AArch64 assembly (AAPCS64).
#
//   .include "anubis.inc"
#
// Status codes come back in w0: 0 ok, 1 argument error, 2 unsolved, 3 internal.
#
// AArch64 divides integer and floating arguments into two independent register
// sequences: x0..x7 for integers, d0..d7 for floats. Take
//   int anubis_solve_nibbles(const char *challenge, int difficulty, int threads,
//                            int64_t max_nonce, double budget_ms,
//                            uint64_t *out_nonce, char *out_hex, double *out_ms)
// and the arguments land in x0, w1, w2, x3, d0, x4, x5, x6 — the double takes a
// slot in the float sequence, not one of x4..x7, so everything after it shifts
// down by one compared to a naive reading. Nothing reaches the stack: eight
// arguments, seven integer slots needed. That is the one place AArch64 is
// friendlier than x86-64 here, where the eighth argument is pushed.

// ---------------------------------------------------------------- introspection
.macro ANUBIS_VERSION
    bl anubis_solver_version
.endm

.macro ANUBIS_GPU_INFO
    bl anubis_gpu_info
.endm

.macro ANUBIS_AFFINITY
    bl anubis_cpu_affinity_info
.endm

.macro ANUBIS_DEFAULT_THREADS
    bl anubis_default_threads
.endm

.macro ANUBIS_BATCH_WIDTH
    bl anubis_batch_width
.endm

.macro ANUBIS_SET_GPU_VERIFY enable
    mov w0, #\enable
    bl anubis_set_gpu_verify
.endm

// a position-independent address into \reg (adrp + :lo12: pair)
.macro ANUBIS_ADR reg, sym
    adrp \reg, \sym
    add  \reg, \reg, :lo12:\sym
.endm

// --------------------------------------------------------- solving, 7 arguments
.macro ANUBIS_SOLVE sym, challenge, difficulty, threads, max_nonce, out_nonce, out_hex, out_ms
    ANUBIS_ADR x0, \challenge
    mov  w1, #\difficulty
    mov  w2, #\threads
    mov  x3, #\max_nonce
    fmov d0, xzr                       // budget_ms = 0.0
    ANUBIS_ADR x4, \out_nonce          // 6th arg: x4, because d0 takes no x slot
    ANUBIS_ADR x5, \out_hex            // 7th arg
    ANUBIS_ADR x6, \out_ms             // 8th arg
    bl   \sym
.endm

.macro ANUBIS_SOLVE_NIBBLES challenge, difficulty, threads, max_nonce, out_nonce, out_hex, out_ms
    ANUBIS_SOLVE anubis_solve_nibbles, \challenge, \difficulty, \threads, \max_nonce, \out_nonce, \out_hex, \out_ms
.endm

.macro ANUBIS_SOLVE_BITS challenge_hex, difficulty, threads, out_nonce, out_hex, out_ms
    ANUBIS_SOLVE anubis_solve_bits, \challenge_hex, \difficulty, \threads, -1, \out_nonce, \out_hex, \out_ms
.endm

.macro ANUBIS_SOLVE_ARGON2ID challenge_hex, difficulty, threads, out_nonce, out_hex, out_ms
    ANUBIS_SOLVE anubis_solve_argon2id, \challenge_hex, \difficulty, \threads, -1, \out_nonce, \out_hex, \out_ms
.endm

.macro ANUBIS_SOLVE_HASHX challenge_hex, difficulty, threads, out_nonce, out_hex, out_ms
    ANUBIS_SOLVE anubis_solve_hashx, \challenge_hex, \difficulty, \threads, -1, \out_nonce, \out_hex, \out_ms
.endm

// ------------------------------------------------------------------ verifying
// int anubis_verify_*(const char *, <nonce>, int, char *)  -> x0, x1, w2, x3
.macro ANUBIS_VERIFY sym, challenge, nonce, difficulty, out_hex
    ANUBIS_ADR x0, \challenge
    ldr  x1, \nonce
    mov  w2, #\difficulty
    ANUBIS_ADR x3, \out_hex
    bl   \sym
.endm

.macro ANUBIS_VERIFY_NIBBLES challenge, nonce, difficulty, out_hex
    ANUBIS_VERIFY anubis_verify_nibbles, \challenge, \nonce, \difficulty, \out_hex
.endm

// ------------------------------------------------------------------- sha256
.macro ANUBIS_SHA256_HEX data, len, out_hex
    ANUBIS_ADR x0, \data
    mov  x1, #\len
    ANUBIS_ADR x2, \out_hex
    bl   anubis_sha256_hex
.endm
