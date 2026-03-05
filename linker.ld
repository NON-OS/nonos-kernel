ENTRY(_start)
OUTPUT_ARCH(i386:x86-64)
OUTPUT_FORMAT(elf64-x86-64)

/* Position-independent executable - can be loaded at any address */
PHDRS {
    text    PT_LOAD FLAGS(5);  /* r-x */
    rodata  PT_LOAD FLAGS(4);  /* r-- */
    data    PT_LOAD FLAGS(6);  /* rw- */
    dynamic PT_DYNAMIC FLAGS(6); /* rw- for dynamic info */
}

SECTIONS {
    /* Start at 0 - will be relocated by bootloader */
    . = 0;

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

    /* NONOS Manifest and Signature sections - MUST come BEFORE .bss
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

    /* BSS must be LAST loadable section - it's NOBITS so won't bloat the binary */
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

    /* Relocation tables for PIE - needed by bootloader */
    .rela.dyn ALIGN(8) : {
        *(.rela.init)
        *(.rela.text .rela.text.* .rela.gnu.linkonce.t.*)
        *(.rela.fini)
        *(.rela.rodata .rela.rodata.* .rela.gnu.linkonce.r.*)
        *(.rela.data .rela.data.* .rela.gnu.linkonce.d.*)
        *(.rela.tdata .rela.tdata.* .rela.gnu.linkonce.td.*)
        *(.rela.tbss .rela.tbss.* .rela.gnu.linkonce.tb.*)
        *(.rela.ctors)
        *(.rela.dtors)
        *(.rela.got)
        *(.rela.bss .rela.bss.* .rela.gnu.linkonce.b.*)
        *(.rela.dyn)
        *(.rela.plt)
        *(.rela*)
    } :data

    /* Dynamic section for PIE */
    .dynamic ALIGN(8) : {
        *(.dynamic)
    } :data :dynamic

    /* GOT for position-independent code */
    .got ALIGN(8) : {
        *(.got)
        *(.got.plt)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.debug*)
        *(.plt*)
    }
}