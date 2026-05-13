/* EL1 vector table. 16 entries x 0x80, 2KB-aligned. VBAR_EL1 install
 * point lives in exceptions::install. Frame layout matches
 * exceptions::frame::ExceptionFrame (288 bytes, repr(C)). */

.section .text.vectors, "ax", %progbits

/* 31 GPRs + sp + elr + spsr + esr + far = 36*8 = 288. */
.equ FRAME_SIZE, 288

.macro SAVE_GPRS
    sub     sp, sp, #FRAME_SIZE
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]
.endm

.macro SAVE_SYSREGS_KERNEL
    /* Pre-exception kernel sp = sp + FRAME_SIZE. */
    add     x0, sp, #FRAME_SIZE
    str     x0,       [sp, #248]
    mrs     x0, elr_el1
    mrs     x1, spsr_el1
    stp     x0, x1,   [sp, #256]
    mrs     x0, esr_el1
    mrs     x1, far_el1
    stp     x0, x1,   [sp, #272]
.endm

.macro SAVE_SYSREGS_USER
    mrs     x0, sp_el0
    str     x0,       [sp, #248]
    mrs     x0, elr_el1
    mrs     x1, spsr_el1
    stp     x0, x1,   [sp, #256]
    mrs     x0, esr_el1
    mrs     x1, far_el1
    stp     x0, x1,   [sp, #272]
.endm

.macro RESTORE_GPRS
    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    add     sp, sp, #FRAME_SIZE
.endm

.macro RESTORE_SYSREGS_KERNEL
    ldp     x0, x1,   [sp, #256]
    msr     elr_el1, x0
    msr     spsr_el1, x1
.endm

.macro RESTORE_SYSREGS_USER
    ldr     x0,       [sp, #248]
    msr     sp_el0, x0
    ldp     x0, x1,   [sp, #256]
    msr     elr_el1, x0
    msr     spsr_el1, x1
.endm

/* Vector table. Each slot is exactly 0x80 bytes; we use one branch and
 * leave the assembler to pad. */
.balign 0x800
.globl __aarch64_vectors_el1
.type  __aarch64_vectors_el1, %function
__aarch64_vectors_el1:

    /* Current EL with SP_EL0 — kernel uses SPx; SP0 is a bug. */
    .balign 0x80
    b   __aarch64_invalid_sp0
    .balign 0x80
    b   __aarch64_invalid_sp0
    .balign 0x80
    b   __aarch64_invalid_sp0
    .balign 0x80
    b   __aarch64_invalid_sp0

    /* Current EL with SP_ELx — kernel mode. */
    .balign 0x80
    b   __aarch64_sync_current
    .balign 0x80
    b   __aarch64_irq_current
    .balign 0x80
    b   __aarch64_fiq_current
    .balign 0x80
    b   __aarch64_serror_current

    /* Lower EL using AArch64 — user mode (CPL=3 equivalent). */
    .balign 0x80
    b   __aarch64_sync_lower
    .balign 0x80
    b   __aarch64_irq_lower
    .balign 0x80
    b   __aarch64_fiq_lower
    .balign 0x80
    b   __aarch64_serror_lower

    /* Lower EL using AArch32 — unsupported. */
    .balign 0x80
    b   __aarch64_invalid_aarch32
    .balign 0x80
    b   __aarch64_invalid_aarch32
    .balign 0x80
    b   __aarch64_invalid_aarch32
    .balign 0x80
    b   __aarch64_invalid_aarch32

.size __aarch64_vectors_el1, . - __aarch64_vectors_el1

/* Entry stubs. Each saves the frame, calls the Rust handler with x0 =
 * frame pointer, then restores and erets. A handler that diverges
 * (halt) never reaches the eret path. */

.balign 16
__aarch64_sync_current:
    SAVE_GPRS
    SAVE_SYSREGS_KERNEL
    mov     x0, sp
    bl      aarch64_exc_sync_current
    RESTORE_SYSREGS_KERNEL
    RESTORE_GPRS
    eret

.balign 16
__aarch64_irq_current:
    SAVE_GPRS
    SAVE_SYSREGS_KERNEL
    mov     x0, sp
    bl      aarch64_exc_irq_current
    RESTORE_SYSREGS_KERNEL
    RESTORE_GPRS
    eret

.balign 16
__aarch64_fiq_current:
    SAVE_GPRS
    SAVE_SYSREGS_KERNEL
    mov     x0, sp
    bl      aarch64_exc_fiq_current
    RESTORE_SYSREGS_KERNEL
    RESTORE_GPRS
    eret

.balign 16
__aarch64_serror_current:
    SAVE_GPRS
    SAVE_SYSREGS_KERNEL
    mov     x0, sp
    bl      aarch64_exc_serror_current
    RESTORE_SYSREGS_KERNEL
    RESTORE_GPRS
    eret

.balign 16
__aarch64_sync_lower:
    SAVE_GPRS
    SAVE_SYSREGS_USER
    mov     x0, sp
    bl      aarch64_exc_sync_lower
    RESTORE_SYSREGS_USER
    RESTORE_GPRS
    eret

.balign 16
__aarch64_irq_lower:
    SAVE_GPRS
    SAVE_SYSREGS_USER
    mov     x0, sp
    bl      aarch64_exc_irq_lower
    RESTORE_SYSREGS_USER
    RESTORE_GPRS
    eret

.balign 16
__aarch64_fiq_lower:
    SAVE_GPRS
    SAVE_SYSREGS_USER
    mov     x0, sp
    bl      aarch64_exc_fiq_lower
    RESTORE_SYSREGS_USER
    RESTORE_GPRS
    eret

.balign 16
__aarch64_serror_lower:
    SAVE_GPRS
    SAVE_SYSREGS_USER
    mov     x0, sp
    bl      aarch64_exc_serror_lower
    RESTORE_SYSREGS_USER
    RESTORE_GPRS
    eret

.balign 16
__aarch64_invalid_sp0:
    SAVE_GPRS
    SAVE_SYSREGS_KERNEL
    mov     x0, sp
    bl      aarch64_exc_invalid_sp0
1:  wfi
    b       1b

.balign 16
__aarch64_invalid_aarch32:
    SAVE_GPRS
    SAVE_SYSREGS_USER
    mov     x0, sp
    bl      aarch64_exc_invalid_aarch32
1:  wfi
    b       1b
