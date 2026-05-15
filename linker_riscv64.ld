ENTRY(_start)
OUTPUT_ARCH(riscv)
OUTPUT_FORMAT(elf64-littleriscv)

/* riscv64 kernel image. Linked at 0x80200000 — QEMU virt RAM base
 * (0x80000000) plus 2 MiB OpenSBI reservation. On real hardware the
 * loader places PT_LOAD segments at matching physical addresses per
 * board profile. The kernel runs in Sv39/Sv48/Sv57 once mmu::init_mmu
 * installs the kernel translation; until then accesses are physical. */

PHDRS {
    text   PT_LOAD FLAGS(5);  /* r-x */
    rodata PT_LOAD FLAGS(4);  /* r-- */
    data   PT_LOAD FLAGS(6);  /* rw- */
}

SECTIONS {
    . = 0x80200000;
    __kernel_image_start = .;

    .text ALIGN(0x1000) : {
        *(.text._start)
        *(.text .text.*)
            *(.ltext .ltext.*)
    } :text

    .rodata ALIGN(0x1000) : {
        *(.rodata .rodata.*)
            *(.lrodata .lrodata.*)
        /* RISC-V small-data anchor used by gp-relative addressing. */
        . = ALIGN(0x10);
        __global_pointer$ = . + 0x800;
        *(.sdata2 .sdata2.*)
    } :rodata

    .data ALIGN(0x1000) : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    .nonos.manifest ALIGN(0x1000) : {
        __nonos_manifest_start = .;
        KEEP(*(.nonos.manifest))
        __nonos_manifest_end = .;
    } :data

    .nonos.sig ALIGN(8) : {
        __nonos_signature_start = .;
        KEEP(*(.nonos.sig))
        __nonos_signature_end = .;
    } :data

    .bss ALIGN(0x1000) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } :data

    . = ALIGN(0x1000);
    __stack_bottom = .;
    . += 64K;
    __stack_top = .;

    __kernel_image_end = .;
    _end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.debug*)
        *(.plt*)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.hash)
        *(.gnu.hash)
        *(.rela.*)
        *(.got)
        *(.got.plt)
        *(.interp)
        *(.riscv.attributes)
    }
}
