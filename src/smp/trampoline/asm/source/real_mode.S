.code16
    cli
    cld
    xor     %ax, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    mov     %ax, %fs
    mov     %ax, %gs

    /* A20 via fast gate (port 0x92). Idempotent. */
    in      $0x92, %al
    or      $0x02, %al
    and     $0xFE, %al
    out     %al, $0x92

    /* lgdt [TRAMP_BASE + OFF_GDT32_PTR]. */
    mov     $(TRAMP_BASE + OFF_GDT32_PTR), %eax
    lgdtl   (%eax)

    /* CR0.PE = 1. */
    mov     %cr0, %eax
    or      $0x1, %eax
    mov     %eax, %cr0

    /* far jump to 32-bit code segment, selector 0x08. */
    .byte   0x66, 0xEA
    .long   (TRAMP_BASE + OFF_PMODE)
    .word   0x08
