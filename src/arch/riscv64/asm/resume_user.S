/* riscv64 resume-from-preempt to U-mode.
 *
 * extern "C" fn riscv64_resume_user(saved: *const SavedUser) -> !
 *
 * a0 = saved. Layout (src/arch/riscv64/context/types.rs::SavedUser):
 *      0..248  gprs[0..31]  =  x1..x31 in numeric order
 *    248       sepc
 *    256       sstatus
 *    264       kernel_sp  (primes sscratch so next trap-from-user swaps)
 *
 * gprs index → arch register:
 *   0=ra(x1)  1=sp(x2)  2=gp(x3)  3=tp(x4)  4=t0(x5)  5=t1(x6)  6=t2(x7)
 *   7=s0(x8)  8=s1(x9)  9=a0(x10) 10=a1(x11) ... 16=a7(x17)
 *  17=s2..   26=s11(x27) 27=t3(x28) ... 30=t6(x31)
 */

.section .text.resume_user, "ax", %progbits

.balign 4
.globl riscv64_resume_user
.type  riscv64_resume_user, @function
riscv64_resume_user:
    /* sysregs via t0 scratch; gprs[4] (= t0) is restored last below. */
    ld      t0, 248(a0)
    csrw    sepc, t0
    ld      t0, 256(a0)
    csrw    sstatus, t0
    ld      t0, 264(a0)
    csrw    sscratch, t0

    /* Restore every GPR except sp (last) and a0 (very last) and t0
     * (kept as scratch until just before sp). */
    ld      ra,    0(a0)         /* x1  */
    ld      gp,   16(a0)         /* x3  */
    ld      tp,   24(a0)         /* x4  */
    ld      t1,   40(a0)         /* x6  */
    ld      t2,   48(a0)         /* x7  */
    ld      s0,   56(a0)         /* x8  */
    ld      s1,   64(a0)         /* x9  */
    ld      a1,   80(a0)         /* x11 */
    ld      a2,   88(a0)         /* x12 */
    ld      a3,   96(a0)         /* x13 */
    ld      a4,  104(a0)         /* x14 */
    ld      a5,  112(a0)         /* x15 */
    ld      a6,  120(a0)         /* x16 */
    ld      a7,  128(a0)         /* x17 */
    ld      s2,  136(a0)         /* x18 */
    ld      s3,  144(a0)         /* x19 */
    ld      s4,  152(a0)         /* x20 */
    ld      s5,  160(a0)         /* x21 */
    ld      s6,  168(a0)         /* x22 */
    ld      s7,  176(a0)         /* x23 */
    ld      s8,  184(a0)         /* x24 */
    ld      s9,  192(a0)         /* x25 */
    ld      s10, 200(a0)         /* x26 */
    ld      s11, 208(a0)         /* x27 */
    ld      t3,  216(a0)         /* x28 */
    ld      t4,  224(a0)         /* x29 */
    ld      t5,  232(a0)         /* x30 */
    ld      t6,  240(a0)         /* x31 */

    /* sp (gprs[1]) just before scratch-t0 + a0. */
    ld      sp,    8(a0)

    /* t0 last before a0 — frees the scratch we used for sysregs. */
    ld      t0,   32(a0)         /* x5 */

    /* a0 last (overwrites ctx pointer with gprs[9] = a0). */
    ld      a0,   72(a0)

    sret

.size riscv64_resume_user, . - riscv64_resume_user
