.code64
nonos_ap_lmode:
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %fs
    mov     %ax, %gs
    mov     %ax, %ss

    /* Load per-AP stack top, set rsp, align, zero rbp. */
    mov     (TRAMP_BASE + OFF_STACK), %rsp
    and     $-16, %rsp
    xor     %rbp, %rbp

    /* SysV first arg: cpu_id. */
    mov     (TRAMP_BASE + OFF_CPU_ID), %edi

    /* Mark ready before jumping so BSP can rearm trampoline data. */
    movl    $1, (TRAMP_BASE + OFF_READY)

    /* Jump through stored 64-bit entry pointer. */
    mov     (TRAMP_BASE + OFF_ENTRY), %rax
    jmp     *%rax
