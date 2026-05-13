/* aarch64 resume-from-preempt to EL0.
 *
 * extern "C" fn aarch64_resume_user(saved: *const SavedUser) -> !
 *
 * x0 = saved. Layout (matches src/arch/aarch64/context/types.rs::SavedUser):
 *     0    gprs[0..31]  x0..x30 in numeric order, 8 bytes each      (= 248 bytes)
 *   248    sp_el0
 *   256    elr_el1
 *   264    spsr_el1
 *   272    kernel_sp
 *
 * IRQs masked on entry. eret restores SPSR.DAIF for EL0. */

.section .text.resume_user, "ax", %progbits

.balign 16
.globl aarch64_resume_user
.type  aarch64_resume_user, %function
aarch64_resume_user:
    /* sysregs first; x9 is our scratch until we load gprs[9] near the end. */
    ldr     x9,  [x0, #248]
    msr     sp_el0, x9
    ldr     x9,  [x0, #256]
    msr     elr_el1, x9
    ldr     x9,  [x0, #264]
    msr     spsr_el1, x9
    ldr     x9,  [x0, #272]
    mov     sp,  x9

    /* x2..x7 from gprs[2..7]. */
    ldp     x2,  x3,  [x0, #16]
    ldp     x4,  x5,  [x0, #32]
    ldp     x6,  x7,  [x0, #48]

    /* x10..x29 (skip x8/x9 — handled below). */
    ldp     x10, x11, [x0, #80]
    ldp     x12, x13, [x0, #96]
    ldp     x14, x15, [x0, #112]
    ldp     x16, x17, [x0, #128]
    ldp     x18, x19, [x0, #144]
    ldp     x20, x21, [x0, #160]
    ldp     x22, x23, [x0, #176]
    ldp     x24, x25, [x0, #192]
    ldp     x26, x27, [x0, #208]
    ldp     x28, x29, [x0, #224]

    /* x30 alone at offset 240. */
    ldr     x30, [x0, #240]

    /* x8 alone, then x9 last before x0/x1 — x9 is our scratch above. */
    ldr     x8,  [x0, #64]
    ldr     x9,  [x0, #72]

    /* x0,x1: x0 is still the ctx pointer; ldp computes the address
     * from x0's current value before writing, so loading into x0 here
     * is well-defined. */
    ldp     x0,  x1,  [x0, #0]

    isb
    eret

.size aarch64_resume_user, . - aarch64_resume_user
