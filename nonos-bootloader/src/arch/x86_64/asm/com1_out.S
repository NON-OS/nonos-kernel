/* NØNOS Operating System
 * Copyright (C) 2026 NØNOS Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

/* Single-byte write to COM1 (port 0x3F8). The bootloader uses
 * this for late-stage post-codes after UEFI Boot Services have
 * been exited, when no other I/O is available.
 *
 * Caller (Rust):
 *   pub unsafe extern "C" fn nonos_arch_com1_out(byte: u8);
 *
 * x86_64-unknown-uefi (Microsoft x64 ABI): the byte arrives in
 * the low 8 bits of %rcx, so we use %cl.
 */

.global nonos_arch_com1_out
nonos_arch_com1_out:
    mov %cl, %al
    mov $0x3F8, %dx
    out %al, %dx
    ret
