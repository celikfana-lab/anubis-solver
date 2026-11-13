# asm_min.s — the smallest useful assembly binding: no libc, no startup files.
#
#   cc -nostdlib -no-pie -o /tmp/asm_min examples/asm_min.s \
#      -L. -lanubis_solver -Wl,-rpath,$PWD
#   /tmp/asm_min        -> libanubis_solver 1.1.0
#
# It calls anubis_solver_version, measures the string, writes it with the raw
# write(2) syscall and exits. The full macro set and a solving demo are in
# bindings/asm/.
    .text
    .globl _start
    .type _start, @function
_start:
    call anubis_solver_version@PLT       # -> %rax = const char *
    mov  %rax, %rsi                      # write() buffer
    mov  %rax, %rdi
    xor  %rcx, %rcx                      # strlen, inline
1:  cmpb $0, (%rdi, %rcx)
    je   2f
    inc  %rcx
    jmp  1b
2:  mov  %rcx, %rdx                      # write() count
    mov  $1, %edi                        # fd = stdout
    mov  $1, %eax                        # SYS_write
    syscall

    mov  $60, %eax                       # SYS_exit
    xor  %edi, %edi
    syscall

    .section .note.GNU-stack,"",@progbits
