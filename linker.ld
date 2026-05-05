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

    /* Relocation tables for PIE - needed by bootloader. Placed before
       BSS so that BSS stays the LAST loadable section in :data and
       remains NOBITS on disk. Putting these after BSS forces the
       linker to materialise the entire BSS gap in the file. */
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

    /* BSS is the LAST loadable section in :data. Nothing real follows,
       so the linker keeps it NOBITS and the kernel image stays small
       no matter how much zero-init static data the kernel grows. */
    .bss ALIGN(0x1000) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /* Stack reservation. NOBITS-equivalent: no section follows in
       :data, so the linker does not materialise these bytes. */
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
        *(.plt*)
    }
}