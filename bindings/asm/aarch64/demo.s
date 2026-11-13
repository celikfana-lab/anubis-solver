// demo.s — solve an Anubis challenge from pure AArch64 assembly.
#
//   make run-arm      (from bindings/asm; needs an aarch64 build of the library)
    .include "anubis.inc"

    .section .rodata
challenge:  .asciz "demo-challenge"
fmt_ver:    .asciz "libanubis_solver %s\n"
fmt_gpu:    .asciz "gpu: %s | threads %d | batch %d\n"
fmt_ok:     .asciz "nonce %lu  hash %s  %.3f ms\n"
fmt_fail:   .asciz "solve failed: %d\n"
fmt_check:  .asciz "verify: %s\n"
s_ok:       .asciz "ok"
s_bad:      .asciz "FAILED"
s_none:     .asciz "(none)"

    .bss
    .align 4
snonce:     .skip 8
shex:       .skip 65
sms:        .skip 8
vhex:       .skip 65
gpu_ptr:    .skip 8
gpu_threads: .skip 4
gpu_batch:  .skip 4

    .text
    .globl main
    .type main, %function
main:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    // ---- library version ----
    ANUBIS_VERSION
    mov x1, x0
    ANUBIS_ADR x0, fmt_ver
    bl printf

    // ---- gpu / threads / batch ----
    ANUBIS_GPU_INFO
    cbnz x0, 1f
    ANUBIS_ADR x0, s_none
1:  ANUBIS_ADR x9, gpu_ptr
    str x0, [x9]

    ANUBIS_DEFAULT_THREADS
    ANUBIS_ADR x9, gpu_threads
    str w0, [x9]

    ANUBIS_BATCH_WIDTH
    ANUBIS_ADR x9, gpu_batch
    str w0, [x9]

    ANUBIS_ADR x0, fmt_gpu
    ANUBIS_ADR x9, gpu_ptr
    ldr x1, [x9]
    ANUBIS_ADR x9, gpu_threads
    ldr w2, [x9]
    ANUBIS_ADR x9, gpu_batch
    ldr w3, [x9]
    bl printf

    // ---- solve: 3 leading zero nibbles ----
    ANUBIS_SOLVE_NIBBLES challenge, 3, 0, -1, snonce, shex, sms
    cbnz w0, Lsolve_failed

    ANUBIS_ADR x0, fmt_ok
    ANUBIS_ADR x9, snonce
    ldr x1, [x9]
    ANUBIS_ADR x2, shex
    ANUBIS_ADR x9, sms
    ldr d0, [x9]
    bl printf

    // ---- verify ----
    ANUBIS_VERIFY_NIBBLES challenge, snonce, 3, vhex
    ANUBIS_ADR x1, s_ok
    cbz w0, 2f
    ANUBIS_ADR x1, s_bad
2:  ANUBIS_ADR x0, fmt_check
    bl printf

    mov w0, #0
    ldp x29, x30, [sp], #16
    ret

Lsolve_failed:
    mov w1, w0
    ANUBIS_ADR x0, fmt_fail
    bl printf
    mov w0, #1
    ldp x29, x30, [sp], #16
    ret

    .section .note.GNU-stack,"",@progbits
