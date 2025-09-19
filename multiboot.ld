/* Simple linker script for multiboot kernel */

ENTRY(_start)

SECTIONS
{
    . = 0x00100000;

    .multiboot ALIGN(4K) :
    {
        *(.multiboot)
    }

    .text ALIGN(4K) :
    {
        *(.text)
        *(.text.*)
    }

    .rodata ALIGN(4K) :
    {
        *(.rodata)
        *(.rodata.*)
    }

    .data ALIGN(4K) :
    {
        *(.data)
        *(.data.*)
    }

    .bss ALIGN(4K) :
    {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }
}