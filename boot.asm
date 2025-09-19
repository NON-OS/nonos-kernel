; Multiboot header for kernel
section .multiboot_header
header_start:
    ; Multiboot magic number
    dd 0x1BADB002
    ; Flags
    dd 0x00000003
    ; Checksum
    dd -(0x1BADB002 + 0x00000003)
header_end:

section .text
bits 32
global _start

_start:
    ; Set up stack
    mov esp, stack_top
    
    ; Call our Rust main function
    extern rust_main
    call rust_main
    
    ; Hang if we return
.hang:
    hlt
    jmp .hang

section .bss
stack_bottom:
    resb 4096 * 4  ; 16KB stack
stack_top: