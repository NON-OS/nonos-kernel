.code32
nonos_ap_pmode:
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %fs
    mov     %ax, %gs
    mov     %ax, %ss

    /* CR4: PAE | PSE | OSFXSR | OSXMMEXCPT. */
    mov     %cr4, %eax
    or      $((1<<5) | (1<<4) | (1<<9) | (1<<10)), %eax
    mov     %eax, %cr4

    /* CR3 = BSP PML4 (low 32 bits). */
    mov     (TRAMP_BASE + OFF_PML4), %eax
    mov     %eax, %cr3

    /* EFER.LME | NXE. */
    mov     $0xC0000080, %ecx
    rdmsr
    or      $((1<<8) | (1<<11)), %eax
    wrmsr

    /* CR0.PG | CR0.WP | CR0.PE. */
    mov     %cr0, %eax
    or      $((1<<31) | (1<<16) | (1<<0)), %eax
    mov     %eax, %cr0

    /* lgdt 64-bit, then far jump into 64-bit code segment 0x08. */
    mov     $(TRAMP_BASE + OFF_GDT64_PTR), %eax
    lgdt    (%eax)

    ljmp    $0x08, $(TRAMP_BASE + OFF_LMODE)
