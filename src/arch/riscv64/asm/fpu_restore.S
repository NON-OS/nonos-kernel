/* riscv64 LP64D FP restore. a0 = &FpContext (8-aligned).
 * Caller must have sstatus.FS != Off granting FP access. */

.section .text.riscv64_fpu_restore, "ax", %progbits
.balign 4
.globl riscv64_fpu_restore
.type  riscv64_fpu_restore, @function

riscv64_fpu_restore:
    lw      t0, 256(a0)
    fscsr   t0

    fld     f0,    0(a0)
    fld     f1,    8(a0)
    fld     f2,   16(a0)
    fld     f3,   24(a0)
    fld     f4,   32(a0)
    fld     f5,   40(a0)
    fld     f6,   48(a0)
    fld     f7,   56(a0)
    fld     f8,   64(a0)
    fld     f9,   72(a0)
    fld     f10,  80(a0)
    fld     f11,  88(a0)
    fld     f12,  96(a0)
    fld     f13, 104(a0)
    fld     f14, 112(a0)
    fld     f15, 120(a0)
    fld     f16, 128(a0)
    fld     f17, 136(a0)
    fld     f18, 144(a0)
    fld     f19, 152(a0)
    fld     f20, 160(a0)
    fld     f21, 168(a0)
    fld     f22, 176(a0)
    fld     f23, 184(a0)
    fld     f24, 192(a0)
    fld     f25, 200(a0)
    fld     f26, 208(a0)
    fld     f27, 216(a0)
    fld     f28, 224(a0)
    fld     f29, 232(a0)
    fld     f30, 240(a0)
    fld     f31, 248(a0)

    ret

.size riscv64_fpu_restore, . - riscv64_fpu_restore
