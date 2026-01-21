// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::arch::asm;
use crate::arch::x86_64::gdt::constants::*;

/// # Safety: Immediately after loading a new GDT.
#[inline]
pub(crate) unsafe fn reload_segments_internal() { unsafe {
    asm!(
        "push {sel}",
        "lea {tmp}, [rip + 2f]",
        "push {tmp}",
        "retfq",
        "2:",
        sel = in(reg) SEL_KERNEL_CODE as u64,
        tmp = out(reg) _,
        options(preserves_flags)
    );

    asm!(
        "mov ds, {sel:x}",
        "mov es, {sel:x}",
        "mov ss, {sel:x}",
        sel = in(reg) SEL_KERNEL_DATA as u32,
        options(nomem, nostack, preserves_flags)
    );

    asm!(
        "xor eax, eax",
        "mov fs, ax",
        "mov gs, ax",
        out("eax") _,
        options(nomem, nostack)
    );
}}

/// # Safety: GDT must be loaded first.
pub unsafe fn reload_segments() { unsafe {
    reload_segments_internal();
}}
