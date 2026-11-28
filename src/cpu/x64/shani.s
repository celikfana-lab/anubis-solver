/*
 * shani.s — SHA-256 single-block compression with Intel SHA extensions.
 *
 *   void sha256_block_shani(uint32_t state[8], const uint8_t block[64]);
 *
 * Folds one 64-byte block into an existing midstate (state is updated in
 * place). This is the hot path for `fast`/`slow`/`sha256` on CPUs that have
 * the SHA extension: one block costs roughly 80 cycles instead of ~600.
 *
 * Written for the System V AMD64 ABI; no stack is used.
 *
 * The state is kept in the layout the SHA instructions want:
 *     xmm1 = (A, B, E, F)      xmm2 = (C, D, G, H)
 * and every SHA256RNDS2 consumes two rounds with xmm0 holding W+K.
 */

    .section .rodata
    .align 16
.Lshani_bsmask:
    .byte 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

    .align 16
.Lshani_k:
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

    .text
    .globl sha256_block_shani
    .hidden sha256_block_shani
    .type sha256_block_shani, @function

/* Two rounds: xmm0 = W+K, xmm1 = ABEF, xmm2 = CDGH. */
.macro RNDS2_PAIR
    sha256rnds2 %xmm0, %xmm1, %xmm2
    pshufd      $0x0E, %xmm0, %xmm0
    sha256rnds2 %xmm0, %xmm2, %xmm1
.endm

/* One group of four rounds whose message words are already in \reg. */
.macro RNDS2_K reg, off
    movdqa .Lshani_k+\off(%rip), %xmm0
    paddd  \reg, %xmm0
.endm

/* cur += msg2(cur, src) and dst += msg1(dst, src) after the alignr. */
.macro SCHED cur, other, n1, n2
    movdqa   \cur, %xmm7
    palignr  $4, \other, %xmm7
    paddd    %xmm7, \n1
    sha256msg2 \cur, \n1
    sha256msg1 \cur, \n2
.endm

sha256_block_shani:
    /* Load and reorder the midstate into (ABEF, CDGH). */
    movdqu    (%rdi), %xmm3
    movdqu    16(%rdi), %xmm4
    pshufd    $0xB1, %xmm3, %xmm0
    pshufd    $0x1B, %xmm4, %xmm4
    movdqa    %xmm0, %xmm1
    palignr   $8, %xmm4, %xmm1
    pblendw   $0xF0, %xmm0, %xmm4
    movdqa    %xmm1, %xmm8          /* ABEF save */
    movdqa    %xmm4, %xmm9          /* CDGH save */
    movdqa    %xmm4, %xmm2
    movdqa    .Lshani_bsmask(%rip), %xmm10

    /* Rounds 0-3 */
    movdqu    0(%rsi), %xmm3
    pshufb    %xmm10, %xmm3
    RNDS2_K   %xmm3, 0
    RNDS2_PAIR

    /* Rounds 4-7 */
    movdqu    16(%rsi), %xmm4
    pshufb    %xmm10, %xmm4
    RNDS2_K   %xmm4, 16
    RNDS2_PAIR
    sha256msg1 %xmm4, %xmm3

    /* Rounds 8-11 */
    movdqu    32(%rsi), %xmm5
    pshufb    %xmm10, %xmm5
    RNDS2_K   %xmm5, 32
    RNDS2_PAIR
    sha256msg1 %xmm5, %xmm4

    /* Rounds 12-15 */
    movdqu    48(%rsi), %xmm6
    pshufb    %xmm10, %xmm6
    RNDS2_K   %xmm6, 48
    sha256rnds2 %xmm0, %xmm1, %xmm2
    movdqa    %xmm6, %xmm7
    palignr   $4, %xmm5, %xmm7
    paddd     %xmm7, %xmm3
    sha256msg2 %xmm6, %xmm3
    pshufd    $0x0E, %xmm0, %xmm0
    sha256rnds2 %xmm0, %xmm2, %xmm1
    sha256msg1 %xmm6, %xmm5

    /* Rounds 16-63, four rounds per group. After each group the message
     * vectors rotate: 16-19 processes MSG0, 20-23 MSG1, and so on. */
    RNDS2_K   %xmm3, 64
    RNDS2_PAIR
    SCHED     %xmm3, %xmm6, %xmm4, %xmm6

    RNDS2_K   %xmm4, 80
    RNDS2_PAIR
    SCHED     %xmm4, %xmm3, %xmm5, %xmm3

    RNDS2_K   %xmm5, 96
    RNDS2_PAIR
    SCHED     %xmm5, %xmm4, %xmm6, %xmm4

    RNDS2_K   %xmm6, 112
    RNDS2_PAIR
    SCHED     %xmm6, %xmm5, %xmm3, %xmm5

    RNDS2_K   %xmm3, 128
    RNDS2_PAIR
    SCHED     %xmm3, %xmm6, %xmm4, %xmm6

    RNDS2_K   %xmm4, 144
    RNDS2_PAIR
    SCHED     %xmm4, %xmm3, %xmm5, %xmm3

    RNDS2_K   %xmm5, 160
    RNDS2_PAIR
    SCHED     %xmm5, %xmm4, %xmm6, %xmm4

    RNDS2_K   %xmm6, 176
    RNDS2_PAIR
    SCHED     %xmm6, %xmm5, %xmm3, %xmm5

    RNDS2_K   %xmm3, 192
    RNDS2_PAIR
    SCHED     %xmm3, %xmm6, %xmm4, %xmm6

    RNDS2_K   %xmm4, 208
    RNDS2_PAIR
    SCHED     %xmm4, %xmm3, %xmm5, %xmm3

    RNDS2_K   %xmm5, 224
    RNDS2_PAIR
    SCHED     %xmm5, %xmm4, %xmm6, %xmm4

    /* Rounds 60-63: no schedule updates left. */
    RNDS2_K   %xmm6, 240
    RNDS2_PAIR

    /* Add the saved midstate and store. */
    paddd     %xmm8, %xmm1
    paddd     %xmm9, %xmm2
    pshufd    $0xB1, %xmm2, %xmm2
    pshufd    $0x1B, %xmm1, %xmm1
    movdqa    %xmm1, %xmm0
    pblendw   $0xF0, %xmm2, %xmm0
    palignr   $8, %xmm1, %xmm2
    movdqu    %xmm0, (%rdi)
    movdqu    %xmm2, 16(%rdi)
    ret
    .size sha256_block_shani, .-sha256_block_shani

    .section .note.GNU-stack,"",@progbits
