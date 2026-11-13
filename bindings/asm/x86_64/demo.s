# demo.s — solve an Anubis challenge from pure x86-64 assembly.
#
#   make run
#
# Links against libanubis_solver.so with the ordinary dynamic linker; the only
# libc used here is printf, and the calls into the library are all through the
# macros in anubis.inc.
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
    .align 16
snonce:     .skip 8
shex:       .skip 65
sms:        .skip 8
vhex:       .skip 65
gpu_ptr:    .skip 8

    .text
    .globl main
    .type main, @function
main:
    push %rbp
    mov %rsp, %rbp

    # ---- library version -------------------------------------------------
    ANUBIS_VERSION
    mov %rax, %rsi
    lea fmt_ver(%rip), %rdi
    xor %eax, %eax
    call printf@PLT

    # ---- gpu name, threads, batch width ---------------------------------
    ANUBIS_GPU_INFO
    test %rax, %rax
    jnz 1f
    lea s_none(%rip), %rax
1:  mov %rax, gpu_ptr(%rip)

    ANUBIS_DEFAULT_THREADS
    mov %eax, gpu_threads(%rip)
    ANUBIS_BATCH_WIDTH
    mov %eax, gpu_batch(%rip)

    mov gpu_ptr(%rip), %rsi
    mov gpu_threads(%rip), %edx
    mov gpu_batch(%rip), %ecx
    lea fmt_gpu(%rip), %rdi
    xor %eax, %eax
    call printf@PLT

    # ---- solve: 3 leading zero nibbles ----------------------------------
    # ANUBIS_SOLVE anubis_solve_nibbles, challenge, 3, 0, -1, snonce, shex, sms
    ANUBIS_SOLVE_NIBBLES challenge, 3, 0, -1, snonce, shex, sms
    test %eax, %eax
    jnz .Lsolve_failed

    mov snonce(%rip), %rsi
    lea shex(%rip), %rdx
    movsd sms(%rip), %xmm0
    lea fmt_ok(%rip), %rdi
    mov $1, %eax                       # one vector register used by printf
    call printf@PLT

    # ---- verify the nonce we just found ---------------------------------
    ANUBIS_VERIFY_NIBBLES challenge, snonce, 3, vhex
    lea s_bad(%rip), %rsi
    test %eax, %eax
    jnz 2f
    lea s_ok(%rip), %rsi
2:  lea fmt_check(%rip), %rdi
    xor %eax, %eax
    call printf@PLT

    xor %eax, %eax
    leave
    ret

.Lsolve_failed:
    mov %eax, %esi
    lea fmt_fail(%rip), %rdi
    xor %eax, %eax
    call printf@PLT
    mov $1, %eax
    leave
    ret

    .section .bss
    .align 4
gpu_threads: .skip 4
gpu_batch:   .skip 4

    .section .note.GNU-stack,"",@progbits
