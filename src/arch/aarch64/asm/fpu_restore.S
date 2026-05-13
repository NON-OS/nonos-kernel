/* aarch64 FP/SIMD restore. x0 = &FpSimdContext (16-aligned).
 * Caller must have CPACR_EL1.FPEN granting EL1 FP access. */

.section .text.aarch64_fpu_restore, "ax", %progbits
.balign 16
.globl aarch64_fpu_restore
.type  aarch64_fpu_restore, %function

aarch64_fpu_restore:
    ldr     w1, [x0, #0x200]
    msr     fpsr, x1
    ldr     w1, [x0, #0x204]
    msr     fpcr, x1

    ldp     q0,  q1,  [x0, #0x000]
    ldp     q2,  q3,  [x0, #0x020]
    ldp     q4,  q5,  [x0, #0x040]
    ldp     q6,  q7,  [x0, #0x060]
    ldp     q8,  q9,  [x0, #0x080]
    ldp     q10, q11, [x0, #0x0A0]
    ldp     q12, q13, [x0, #0x0C0]
    ldp     q14, q15, [x0, #0x0E0]
    ldp     q16, q17, [x0, #0x100]
    ldp     q18, q19, [x0, #0x120]
    ldp     q20, q21, [x0, #0x140]
    ldp     q22, q23, [x0, #0x160]
    ldp     q24, q25, [x0, #0x180]
    ldp     q26, q27, [x0, #0x1A0]
    ldp     q28, q29, [x0, #0x1C0]
    ldp     q30, q31, [x0, #0x1E0]

    ret

.size aarch64_fpu_restore, . - aarch64_fpu_restore
