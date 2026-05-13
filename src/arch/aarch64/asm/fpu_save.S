/* aarch64 FP/SIMD save. x0 = &mut FpSimdContext (16-aligned).
 * Caller must have CPACR_EL1.FPEN granting EL1 FP access; otherwise
 * the stp/q* instructions trap. */

.section .text.aarch64_fpu_save, "ax", %progbits
.balign 16
.globl aarch64_fpu_save
.type  aarch64_fpu_save, %function

aarch64_fpu_save:
    stp     q0,  q1,  [x0, #0x000]
    stp     q2,  q3,  [x0, #0x020]
    stp     q4,  q5,  [x0, #0x040]
    stp     q6,  q7,  [x0, #0x060]
    stp     q8,  q9,  [x0, #0x080]
    stp     q10, q11, [x0, #0x0A0]
    stp     q12, q13, [x0, #0x0C0]
    stp     q14, q15, [x0, #0x0E0]
    stp     q16, q17, [x0, #0x100]
    stp     q18, q19, [x0, #0x120]
    stp     q20, q21, [x0, #0x140]
    stp     q22, q23, [x0, #0x160]
    stp     q24, q25, [x0, #0x180]
    stp     q26, q27, [x0, #0x1A0]
    stp     q28, q29, [x0, #0x1C0]
    stp     q30, q31, [x0, #0x1E0]

    mrs     x1, fpsr
    str     w1, [x0, #0x200]
    mrs     x1, fpcr
    str     w1, [x0, #0x204]

    ret

.size aarch64_fpu_save, . - aarch64_fpu_save
