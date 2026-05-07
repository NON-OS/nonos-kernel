/* NØNOS Operating System
 * Copyright (C) 2026 NØNOS Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/* Bootloader -> kernel transfer. Caller (Rust):
 *   pub unsafe extern "C" fn nonos_arch_handoff_jump(
 *       entry: u64, stack: u64, handoff: u64) -> !;
 *
 * The bootloader is built for x86_64-unknown-uefi which uses the
 * Microsoft x64 ABI: arguments arrive in %rcx, %rdx, %r8.
 *
 *   %rcx = entry
 *   %rdx = stack
 *   %r8  = handoff
 *
 * The kernel's `_start` is built for SysV AMD64 and reads its
 * first argument from %rdi, so we move %r8 -> %rdi before the
 * jump. After the jump:
 *
 *   %rax = entry
 *   %rsp = stack (16-byte-aligned by caller)
 *   %rdi = handoff (SysV argument 0)
 *   all other GPRs zeroed.
 *
 * Sequence is one-way: there is no path back to the bootloader.
 */

.global nonos_arch_handoff_jump
nonos_arch_handoff_jump:
    cli
    cld
    mov %rcx, %rax
    mov %rdx, %rsp
    mov %r8,  %rdi
    xor %rbp, %rbp
    xor %rbx, %rbx
    xor %rcx, %rcx
    xor %rdx, %rdx
    xor %rsi, %rsi
    xor %r8,  %r8
    xor %r9,  %r9
    xor %r10, %r10
    xor %r11, %r11
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    xor %r15, %r15
    jmp *%rax
