.balign 8
nonos_ap_gdt32:
    .quad   0x0000000000000000
    .quad   0x00CF9A000000FFFF
    .quad   0x00CF92000000FFFF
nonos_ap_gdt32_end:

nonos_ap_gdt32_ptr:
    .word   nonos_ap_gdt32_end - nonos_ap_gdt32 - 1
    .long   TRAMP_BASE + OFF_GDT32

.balign 8
nonos_ap_gdt64:
    .quad   0x0000000000000000
    .quad   0x00AF9A000000FFFF
    .quad   0x00AF92000000FFFF
nonos_ap_gdt64_end:

nonos_ap_gdt64_ptr:
    .word   nonos_ap_gdt64_end - nonos_ap_gdt64 - 1
    .quad   TRAMP_BASE + OFF_GDT64

.balign 8
nonos_ap_trampoline_pml4:
    .quad   0
nonos_ap_trampoline_stack:
    .quad   0
nonos_ap_trampoline_entry:
    .quad   0
nonos_ap_trampoline_cpu_id:
    .long   0
nonos_ap_trampoline_ready:
    .long   0

.balign 16
nonos_ap_trampoline_end:
