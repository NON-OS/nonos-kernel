/* aarch64 first-entry to EL0.
 *
 * extern "C" fn aarch64_enter_user(ctx: *const UserEntry) -> !
 *
 * x0 = ctx. Layout (matches src/arch/aarch64/context/types.rs::UserEntry):
 *     0    entry      (ELR_EL1)
 *     8    user_sp    (SP_EL0)
 *    16    spsr       (SPSR_EL1)
 *    24    kernel_sp  (SP_EL1 to install before eret)
 *    32    args[0..8] (x0..x7 at eret)
 *
 * On entry IRQs are masked by the caller. The eret crosses to EL0t with
 * SPSR's DAIF (the caller writes SPIE-equivalent bits as it sees fit).
 * FP/SIMD is left in whatever state CPACR_EL1 already has — the lazy-
 * enable trap delivers EL0 FP traps to the fail-closed path until per-
 * PCB FP slot ownership lands. */

.section .text.enter_user, "ax", %progbits

.balign 16
.globl aarch64_enter_user
.type  aarch64_enter_user, %function
aarch64_enter_user:
    /* System regs first, using x9 as scratch (caller-save). */
    ldr     x9,  [x0, #0]
    msr     elr_el1, x9
    ldr     x9,  [x0, #8]
    msr     sp_el0, x9
    ldr     x9,  [x0, #16]
    msr     spsr_el1, x9

    /* Load args x2..x7 in pairs; x0 still holds ctx so do it last. */
    ldp     x2,  x3,  [x0, #(32 + 16)]
    ldp     x4,  x5,  [x0, #(32 + 32)]
    ldp     x6,  x7,  [x0, #(32 + 48)]

    /* Install per-task kernel sp into SP_EL1. After this `mov`, the
     * caller's stack is no longer reachable — the helper does not
     * return, so abandoning it is the contract. */
    ldr     x9,  [x0, #24]
    mov     sp,  x9

    /* x0,x1 last — x0 was the ctx pointer. */
    ldp     x0,  x1,  [x0, #(32 + 0)]

    isb
    eret

.size aarch64_enter_user, . - aarch64_enter_user
