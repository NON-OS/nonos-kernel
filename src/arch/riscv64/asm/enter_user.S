/* riscv64 first-entry to U-mode.
 *
 * extern "C" fn riscv64_enter_user(ctx: *const UserEntry) -> !
 *
 * a0 = ctx. Layout (src/arch/riscv64/context/types.rs::UserEntry):
 *      0    entry      (sepc)
 *      8    user_sp
 *     16    sstatus    (SPP=0, SPIE=1, FS=Off, VS=Off)
 *     24    kernel_sp  (primes sscratch so next trap-from-user can swap)
 *     32    args[0..8] (a0..a7 at sret)
 *
 * Caller has masked SIE and installed the right satp. sret to U-mode
 * with sstatus.SPIE copied into SIE by hardware. */

.section .text.enter_user, "ax", %progbits

.balign 4
.globl riscv64_enter_user
.type  riscv64_enter_user, @function
riscv64_enter_user:
    ld      t0, 0(a0)
    csrw    sepc, t0
    ld      t0, 16(a0)
    csrw    sstatus, t0
    ld      t0, 24(a0)
    csrw    sscratch, t0

    /* args a1..a7 first; a0 still holds ctx. */
    ld      a1, 40(a0)
    ld      a2, 48(a0)
    ld      a3, 56(a0)
    ld      a4, 64(a0)
    ld      a5, 72(a0)
    ld      a6, 80(a0)
    ld      a7, 88(a0)

    /* user sp last before a0; sp is x2, gprs[1] in the user layout. */
    ld      sp, 8(a0)

    /* a0 = args[0]; this overwrites the ctx pointer. */
    ld      a0, 32(a0)

    sret

.size riscv64_enter_user, . - riscv64_enter_user
