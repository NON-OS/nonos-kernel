.section .rodata.nonos_ap_trampoline, "a", @progbits
.balign 16

.set TRAMP_BASE,       0x8000
.set OFF_PML4,         (nonos_ap_trampoline_pml4   - nonos_ap_trampoline_start)
.set OFF_STACK,        (nonos_ap_trampoline_stack  - nonos_ap_trampoline_start)
.set OFF_ENTRY,        (nonos_ap_trampoline_entry  - nonos_ap_trampoline_start)
.set OFF_CPU_ID,       (nonos_ap_trampoline_cpu_id - nonos_ap_trampoline_start)
.set OFF_READY,        (nonos_ap_trampoline_ready  - nonos_ap_trampoline_start)
.set OFF_GDT32,        (nonos_ap_gdt32     - nonos_ap_trampoline_start)
.set OFF_GDT32_PTR,    (nonos_ap_gdt32_ptr - nonos_ap_trampoline_start)
.set OFF_GDT64,        (nonos_ap_gdt64     - nonos_ap_trampoline_start)
.set OFF_GDT64_PTR,    (nonos_ap_gdt64_ptr - nonos_ap_trampoline_start)
.set OFF_PMODE,        (nonos_ap_pmode     - nonos_ap_trampoline_start)
.set OFF_LMODE,        (nonos_ap_lmode     - nonos_ap_trampoline_start)

.global nonos_ap_trampoline_start
.global nonos_ap_trampoline_end
.global nonos_ap_trampoline_pml4
.global nonos_ap_trampoline_stack
.global nonos_ap_trampoline_entry
.global nonos_ap_trampoline_cpu_id
.global nonos_ap_trampoline_ready

nonos_ap_trampoline_start:
