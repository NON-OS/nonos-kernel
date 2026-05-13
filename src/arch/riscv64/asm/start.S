/* riscv64 BSP + AP entry.
 *
 * BSP `_start` is the kernel ELF entry. SBI hands a0=hartid, a1=dtb.
 * The AP entry `_riscv64_secondary_start` is the address handed to
 * sbi_hart_start; SBI calls it with a0=hartid, a1=opaque (the per-hart
 * stack top this kernel chose at hart_start time).
 *
 * Both paths set tp=hartid so cpu::id::hart_id() can read this hart's
 * id directly without touching mhartid (M-mode CSR, faults in S). */

.section .text._start, "ax", %progbits
.balign 4
.globl _start
.type  _start, @function

_start:
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    la      sp, __stack_top

    mv      tp, a0

    /* Preserve SBI args across BSS clear and the stash call. */
    mv      s0, a0
    mv      s1, a1

    la      t0, __bss_start
    la      t1, __bss_end
.L_bss:
    bgeu    t0, t1, .L_bss_done
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       .L_bss
.L_bss_done:

    mv      a0, s0
    call    riscv64_store_boot_hart

    mv      a0, s1
    call    kernel_entry

.L_hang:
    wfi
    j       .L_hang

.size _start, . - _start


.section .text._riscv64_secondary_start, "ax", %progbits
.balign 4
.globl _riscv64_secondary_start
.type  _riscv64_secondary_start, @function

_riscv64_secondary_start:
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    /* SBI opaque (a1) is the stack top picked by the kernel. */
    mv      sp, a1

    /* tp = this hart's id; survives across the C call. */
    mv      tp, a0

    call    riscv64_ap_entry

.L_ap_hang:
    wfi
    j       .L_ap_hang

.size _riscv64_secondary_start, . - _riscv64_secondary_start
