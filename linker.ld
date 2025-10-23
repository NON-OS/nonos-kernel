ENTRY(_start)
OUTPUT_ARCH(i386:x86-64)

SECTIONS {
    /* Load at 1MB physical address */
    . = 0x100000;
    
    .multiboot : {
        KEEP(*(.multiboot))
    }
    
    .text : {
        *(.text._start)
        *(.text .text.*)
    }
    
    .rodata : {
        *(.rodata .rodata.*)
    }
    
    .data : {
        *(.data .data.*)
    }
    
    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        __bss_end = .;
    }
    
    .stack : {
        . += 64K;
        __stack_top = .;
    }
    
    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.debug*)
    }
}