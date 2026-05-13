/* aarch64 kernel ELF entry.
 *   x0  = dtb_ptr (preserved in x19 across EL2 drop)
 *   sp  = bootloader-provided
 *   may be at EL1 or EL2; we always continue at EL1.
 * Symbols: __stack_top, __bss_start, __bss_end from linker.ld.
 * Tail-calls kernel_entry(dtb_ptr). */

.section .text._start, "ax", %progbits
.balign 16
.globl _start
.type  _start, %function

_start:
    mov     x19, x0

    /* Drop to EL1 if firmware left us at EL2. SCTLR_EL1 is set to a
     * safe reset value either way. */
    mrs     x0, CurrentEL
    cmp     x0, #(2 << 2)
    b.ne    .L_at_el1

    mov     x0, #(1 << 31)
    msr     hcr_el2, x0

    /* SCTLR_EL1 reset: MMU/I/D off, RES1 bits 11/20/22/23/28/29. */
    mov     x0, #0x0838
    movk    x0, #0x30C5, lsl #16
    msr     sctlr_el1, x0

    /* SPSR_EL2: return to EL1h with DAIF masked. */
    mov     x0, #0x3C5
    msr     spsr_el2, x0

    adr     x0, .L_at_el1
    msr     elr_el2, x0
    eret

.L_at_el1:
    mov     x0, #0x0838
    movk    x0, #0x30C5, lsl #16
    msr     sctlr_el1, x0
    isb

    /* BSP-only continuation. Secondaries wfe; they come up via PSCI. */
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF
    cbnz    x0, .L_secondary

    adrp    x0, __stack_top
    add     x0, x0, :lo12:__stack_top
    mov     sp, x0

    adrp    x1, __bss_start
    add     x1, x1, :lo12:__bss_start
    adrp    x2, __bss_end
    add     x2, x2, :lo12:__bss_end
.L_bss:
    cmp     x1, x2
    b.hs    .L_bss_done
    str     xzr, [x1], #8
    b       .L_bss
.L_bss_done:

    mov     x0, x19
    bl      kernel_entry

.L_hang:
    wfi
    b       .L_hang

.L_secondary:
    wfe
    b       .L_secondary

.size _start, . - _start


/* AP entry. PSCI CPU_ON arranges for this hart to land here with
 *   x0 = context_id (= stack_top picked by the kernel)
 * and the EL the boot CPU was running at. SCTLR_EL1 is reset to the
 * same safe value as on BSP entry; per-CPU VBAR_EL1 / GIC / timer
 * setup happens in Rust before IRQs are unmasked. */

.section .text._aarch64_secondary_start, "ax", %progbits
.balign 16
.globl _aarch64_secondary_start
.type  _aarch64_secondary_start, %function

_aarch64_secondary_start:
    mov     sp, x0

    mov     x1, #0x0838
    movk    x1, #0x30C5, lsl #16
    msr     sctlr_el1, x1
    isb

    bl      aarch64_ap_entry

.L_ap_hang:
    wfi
    b       .L_ap_hang

.size _aarch64_secondary_start, . - _aarch64_secondary_start
