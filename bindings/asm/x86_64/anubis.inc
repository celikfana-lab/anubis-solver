# anubis.inc — calling libanubis_solver from x86-64 assembly (System V ABI).
#
#   .include "anubis.inc"
#
# Every function in anubis-solver.h returns its status code in %eax:
#   0 ANUBIS_OK, 1 argument error, 2 unsolved/exhausted, 3 internal error.
#
# The register assignment is the part that bites. Take
#   int anubis_solve_nibbles(const char *challenge, int difficulty, int threads,
#                            int64_t max_nonce, double budget_ms,
#                            uint64_t *out_nonce, char *out_hex, double *out_ms)
# The Integer arguments take %rdi, %rsi, %rdx, %rcx, %r8, %r9 in order and the
# double goes to %xmm0 in its own sequence. That means:
#    arg 5 (budget_ms)  -> %xmm0     and %r8 is NOT skipped for a double
#    arg 6 (out_nonce)  -> %r8       (not %r9!)
#    arg 7 (out_hex)    -> %r9
#    arg 8 (out_ms)     -> on the stack, at (%rsp) before the call
# Passing out_nonce in %r9 and out_hex on the stack compiles fine and produces
# garbage — this is the usual way an asm binding goes wrong first.
#
# All macros below clobber %rax, and the ones with a stack argument adjust %rsp
# by 16 bytes, so they must be called with %rsp 16-byte aligned (which it is
# inside a normal function frame after push %rbp).

# ---------------------------------------------------------------- introspection

# const char *anubis_solver_version(void)        -> %rax
.macro ANUBIS_VERSION
    call anubis_solver_version@PLT
.endm

# const char *anubis_gpu_info(void)  -> %rax (NULL when there is no GPU)
.macro ANUBIS_GPU_INFO
    call anubis_gpu_info@PLT
.endm

# const char *anubis_cpu_affinity_info(void)     -> %rax
.macro ANUBIS_AFFINITY
    call anubis_cpu_affinity_info@PLT
.endm

# int anubis_default_threads(void)               -> %eax
.macro ANUBIS_DEFAULT_THREADS
    call anubis_default_threads@PLT
.endm

# int anubis_batch_width(void)                   -> %eax (16 AVX-512, 8 AVX2, 0 scalar)
.macro ANUBIS_BATCH_WIDTH
    call anubis_batch_width@PLT
.endm

# void anubis_set_gpu_verify(int enable)         (%edi = 0 or 1)
.macro ANUBIS_SET_GPU_VERIFY enable
    mov $\enable, %edi
    call anubis_set_gpu_verify@PLT
.endm

# --------------------------------------------------------- solving, 7 arguments
#
# One shape covers all four solve functions, because they differ only in the
# callee symbol: a C string, two ints, a 64-bit bound, a double, and three
# out-parameters.
#
#   ANUBIS_SOLVE anubis_solve_hashx, challenge_hex, 4, 0, out_nonce, out_hex, out_ms
#
# budget_ms is 0.0 (no time limit). Use ANUBIS_SOLVE_BUDGET for a real budget.
.macro ANUBIS_SOLVE sym, challenge, difficulty, threads, max_nonce, out_nonce, out_hex, out_ms
    lea \challenge(%rip), %rdi
    mov $\difficulty, %esi
    mov $\threads, %edx
    mov $\max_nonce, %rcx
    pxor %xmm0, %xmm0                    # budget_ms = 0.0
    lea \out_nonce(%rip), %r8            # 6th arg: %r8, not %r9
    lea \out_hex(%rip), %r9              # 7th arg
    lea \out_ms(%rip), %rax
    sub $16, %rsp                        # 8th arg rides on the stack
    mov %rax, (%rsp)
    call \sym@PLT
    add $16, %rsp
.endm

# the same, with a millisecond budget in \budget (an immediate, or load your own
# value into %xmm0 and call ANUBIS_SOLVE_MM)
.macro ANUBIS_SOLVE_BUDGET sym, challenge, difficulty, threads, max_nonce, budget, out_nonce, out_hex, out_ms
    lea \challenge(%rip), %rdi
    mov $\difficulty, %esi
    mov $\threads, %edx
    mov $\max_nonce, %rcx
    movsd \budget(%rip), %xmm0
    lea \out_nonce(%rip), %r8
    lea \out_hex(%rip), %r9
    lea \out_ms(%rip), %rax
    sub $16, %rsp
    mov %rax, (%rsp)
    call \sym@PLT
    add $16, %rsp
.endm

# README shorthand: fast/slow is the nibbles family, the rest are bits.
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

# ------------------------------------------------------------------ verifying
#
# int anubis_verify_*(const char *challenge, <nonce>, int difficulty, char *out_hex)
# Four arguments, no floats, nothing on the stack: %rdi %rsi %rdx %rcx.
.macro ANUBIS_VERIFY sym, challenge, nonce, difficulty, out_hex
    lea \challenge(%rip), %rdi
    mov \nonce, %rsi
    mov $\difficulty, %edx
    lea \out_hex(%rip), %rcx
    call \sym@PLT
.endm

.macro ANUBIS_VERIFY_NIBBLES challenge, nonce, difficulty, out_hex
    ANUBIS_VERIFY anubis_verify_nibbles, \challenge, \nonce, \difficulty, \out_hex
.endm

.macro ANUBIS_VERIFY_BITS challenge_hex, nonce, difficulty, out_hex
    ANUBIS_VERIFY anubis_verify_bits, \challenge_hex, \nonce, \difficulty, \out_hex
.endm

.macro ANUBIS_VERIFY_ARGON2ID challenge_hex, nonce, difficulty, out_hex
    ANUBIS_VERIFY anubis_verify_argon2id, \challenge_hex, \nonce, \difficulty, \out_hex
.endm

.macro ANUBIS_VERIFY_HASHX challenge_hex, nonce, difficulty, out_hex
    ANUBIS_VERIFY anubis_verify_hashx, \challenge_hex, \nonce, \difficulty, \out_hex
.endm

# ------------------------------------------------------------------- sha256
#
# int anubis_sha256_hex(const char *data, size_t len, char *out_hex)
# int anubis_sha256_midstate(const char *data, size_t len, uint32_t out[8])
.macro ANUBIS_SHA256_HEX data, len, out_hex
    lea \data(%rip), %rdi
    mov $\len, %rsi
    lea \out_hex(%rip), %rdx
    call anubis_sha256_hex@PLT
.endm
