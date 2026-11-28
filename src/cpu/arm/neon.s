/*
 * neon.s — SHA-256 single-block compression for AArch64.
 *
 *   void sha256_block_neon(uint32_t state[8], const uint8_t block[64]);
 *
 * Uses the ARMv8 SHA-2 crypto extensions (sha256h / sha256h2 / sha256su0 /
 * sha256su1), which fold one block in roughly 60 cycles instead of ~600 for
 * the portable C path. One vector register pair holds the working state
 * (A..D in v0, E..H in v1) and four more hold the message schedule.
 *
 * The schedule is updated in place (no register rotation): update the
 * register for the next group from the three that follow it.
 *
 * Runtime dispatch only calls this when HWCAP_SHA2 is set (checked in C);
 * CPUs without the extension use the portable implementation.
 */

    .arch armv8-a+crypto
    .section .rodata
    .align 4
.Lneon_k:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

    .text
    .align 2
    .global sha256_block_neon
    .type sha256_block_neon, %function
sha256_block_neon:
    ld1     {v0.4s, v1.4s}, [x0]        /* state: A..D, E..H */
    mov     v2.16b, v0.16b                /* keep initial state */
    mov     v3.16b, v1.16b
    ld1     {v4.16b, v5.16b, v6.16b, v7.16b}, [x1]
    rev32   v4.16b, v4.16b                /* message words to big-endian */
    rev32   v5.16b, v5.16b
    rev32   v6.16b, v6.16b
    rev32   v7.16b, v7.16b
    adrp    x2, .Lneon_k
    add     x2, x2, :lo12:.Lneon_k

    /* One group of four rounds: wk = schedule + K; abcd/efgh chained. */
    .macro RG s
    ld1     {v16.4s}, [x2], #16
    add     v16.4s, v16.4s, \s\().4s
    mov     v17.16b, v0.16b
    sha256h  q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    .endm

    /* Complete the next four message-schedule words in place. */
    .macro SC d, a, b, c
    sha256su0 \d\().4s, \a\().4s
    sha256su1 \d\().4s, \b\().4s, \c\().4s
    .endm

    RG v4
    RG v5
    RG v6
    RG v7
    SC v4, v5, v6, v7
    RG v4
    SC v5, v6, v7, v4
    RG v5
    SC v6, v7, v4, v5
    RG v6
    SC v7, v4, v5, v6
    RG v7
    SC v4, v5, v6, v7
    RG v4
    SC v5, v6, v7, v4
    RG v5
    SC v6, v7, v4, v5
    RG v6
    SC v7, v4, v5, v6
    RG v7
    SC v4, v5, v6, v7
    RG v4
    SC v5, v6, v7, v4
    RG v5
    SC v6, v7, v4, v5
    RG v6
    SC v7, v4, v5, v6
    RG v7

    add     v0.4s, v0.4s, v2.4s
    add     v1.4s, v1.4s, v3.4s
    st1     {v0.4s, v1.4s}, [x0]
    ret
    .size sha256_block_neon, .-sha256_block_neon
