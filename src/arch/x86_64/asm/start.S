/* Kernel ELF entry. rdi = handoff_ptr.
 * Image linked at 0xFFFFFFFF80000000; ENTRY(_start) in linker.ld. */

.intel_syntax noprefix
.section .text._start, "ax", @progbits
.balign 16
.globl _start
.type  _start, @function

_start:
    cli
    cld

    /* COM1 trace: "NX64\n". */
    mov     dx, 0x3F8
    mov     al, 'N'
    out     dx, al
    mov     al, 'X'
    out     dx, al
    mov     al, '6'
    out     dx, al
    mov     al, '4'
    out     dx, al
    mov     al, 0x0A
    out     dx, al

    push    rdi
    fninit

    /* CR0: clear EM, set MP|NE. */
    mov     rax, cr0
    and     eax, ~(1 << 2)
    or      eax, (1 << 1) | (1 << 5)
    mov     cr0, rax

    /* CR4: set OSFXSR|OSXMMEXCPT, then serialise. */
    mov     rax, cr4
    or      eax, (1 << 9) | (1 << 10)
    mov     cr4, rax
    lfence

    pop     rdi

    and     rsp, -16
    sub     rsp, 8
    call    kernel_entry

.L_hang:
    cli
    hlt
    jmp     .L_hang

.size _start, . - _start
