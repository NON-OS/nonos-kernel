/* NØNOS Operating System
 * Copyright (C) 2026 NØNOS Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/* Bootloader CR3 install. Caller (Rust):
 *   pub unsafe extern "C" fn nonos_arch_load_cr3(pml4_phys: u64);
 *
 * The x86_64-unknown-uefi target uses the Microsoft x64 calling
 * convention; the first integer argument arrives in %rcx, not
 * %rdi.
 *
 * Caller invariants:
 *   - %rcx is a 4-KiB-aligned PML4 physical address.
 *   - The PML4 contains entries that cover the bootloader's
 *     current execution range and stack; otherwise the next
 *     instruction (`ret`) page-faults.
 *   - Interrupts are masked (UEFI Boot Services have already
 *     been exited by the time the bootloader calls this).
 *
 * No .type/.size/.section directives: this file is consumed by
 * Rust's `global_asm!` against the PE/COFF target.
 */

.global nonos_arch_load_cr3
nonos_arch_load_cr3:
    mov %rcx, %cr3
    ret
