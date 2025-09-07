/* Linker script for NØNOS kernel */

ENTRY(_start)

SECTIONS
{
    /* Kernel starts at 1MB */
    . = 0x100000;

    /* Kernel code section */
    .text : {
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata .rodata.*)
    }

    /* Read-write data */
    .data : {
        *(.data .data.*)
    }

    /* Uninitialized data */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /* End of kernel */
    _end = .;
}
