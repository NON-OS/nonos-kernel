/* riscv64 LP64D FP save. a0 = &mut FpContext (8-aligned).
 * Caller must have sstatus.FS != Off granting FP access. */

.section .text.riscv64_fpu_save, "ax", %progbits
.balign 4
.globl riscv64_fpu_save
.type  riscv64_fpu_save, @function

riscv64_fpu_save:
    fsd     f0,    0(a0)
    fsd     f1,    8(a0)
    fsd     f2,   16(a0)
    fsd     f3,   24(a0)
    fsd     f4,   32(a0)
    fsd     f5,   40(a0)
    fsd     f6,   48(a0)
    fsd     f7,   56(a0)
    fsd     f8,   64(a0)
    fsd     f9,   72(a0)
    fsd     f10,  80(a0)
    fsd     f11,  88(a0)
    fsd     f12,  96(a0)
    fsd     f13, 104(a0)
    fsd     f14, 112(a0)
    fsd     f15, 120(a0)
    fsd     f16, 128(a0)
    fsd     f17, 136(a0)
    fsd     f18, 144(a0)
    fsd     f19, 152(a0)
    fsd     f20, 160(a0)
    fsd     f21, 168(a0)
    fsd     f22, 176(a0)
    fsd     f23, 184(a0)
    fsd     f24, 192(a0)
    fsd     f25, 200(a0)
    fsd     f26, 208(a0)
    fsd     f27, 216(a0)
    fsd     f28, 224(a0)
    fsd     f29, 232(a0)
    fsd     f30, 240(a0)
    fsd     f31, 248(a0)

    csrr    t0, fcsr
    sw      t0, 256(a0)

    ret

.size riscv64_fpu_save, . - riscv64_fpu_save
