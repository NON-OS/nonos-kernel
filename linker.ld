ENTRY(_start)
OUTPUT_ARCH(i386:x86-64)
OUTPUT_FORMAT(elf64-x86-64)

/* Force this to be a non-PIE static executable */
PHDRS {
    text    PT_LOAD FLAGS(5);  /* r-x */
    rodata  PT_LOAD FLAGS(4);  /* r-- */
    data    PT_LOAD FLAGS(6);  /* rw- */
}

SECTIONS {
    /* Load at 64MB physical address - well above UEFI/ACPI regions */
    . = 0x4000000;

    .multiboot : {
        KEEP(*(.multiboot))
    } :text

    .text ALIGN(0x1000) : {
        *(.text._start)
        *(.text .text.*)
    } :text

    .rodata ALIGN(0x1000) : {
        *(.rodata .rodata.*)
    } :rodata

    .data ALIGN(0x1000) : {
        *(.data .data.*)
    } :data

    /* NONOS Manifest and Signature sections come BEFORE .bss
       to avoid padding the binary with zeros for the BSS gap */
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

    /* BSS must be LAST loadable section, it's NOBITS so won't bloat the binary */
    .bss ALIGN(0x1000) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /* Stack comes AFTER BSS, at the next page boundary */
    . = ALIGN(0x1000);
    __stack_bottom = .;
    . += 64K;
    __stack_top = .;

    _end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.debug*)
        *(.got*)
        *(.plt*)
        *(.dynamic*)
        *(.dynsym*)
        *(.dynstr*)
        *(.rel*)
        *(.rela*)
    }
}
