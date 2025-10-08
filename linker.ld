ENTRY(_start)
OUTPUT_ARCH(i386:x86-64)

/* Memory layout constants */
KERNEL_VMA = 0xFFFF800000000000;  /* Higher-half virtual base */
KERNEL_LMA = 0x100000;            /* Physical load address (1MB) */

SECTIONS {
    /* Start at the load address */
    . = KERNEL_LMA;
    __kernel_start = .;
    
    /* Multiboot header MUST be early in the file */
    .multiboot : {
        KEEP(*(.multiboot))
    }
    
    /* Boot section - identity mapped */
    .text.boot : {
        __boot_start = .;
        *(.text.boot)
        __boot_end = .;
    }
    
    /* Align to page boundary */
    . = ALIGN(4K);
    
    /* Main kernel sections at higher half */
    . = KERNEL_VMA + ALIGN(., 4K) - KERNEL_LMA;
    
    .text : AT(ADDR(.text) - KERNEL_VMA + KERNEL_LMA) {
        __text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        . = ALIGN(4K);
        __text_end = .;
    }
    
    .rodata : AT(ADDR(.rodata) - KERNEL_VMA + KERNEL_LMA) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        . = ALIGN(4K);
        __rodata_end = .;
    }
    
    .data : AT(ADDR(.data) - KERNEL_VMA + KERNEL_LMA) {
        __data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(4K);
        __data_end = .;
    }
    
    .bss : AT(ADDR(.bss) - KERNEL_VMA + KERNEL_LMA) {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        . = ALIGN(4K);
        __bss_end = .;
    }
    
    /* Boot stack */
    .boot_stack : AT(ADDR(.boot_stack) - KERNEL_VMA + KERNEL_LMA) {
        __boot_stack_start = .;
        . += 64K;
        . = ALIGN(4K);
        __boot_stack_top = .;
    }
    
    __kernel_end = .;
    __kernel_size = __kernel_end - __text_start;
    __kernel_phys_end = __kernel_end - KERNEL_VMA + KERNEL_LMA;
    
    /* Discard sections we don't need */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.debug*)
    }
}