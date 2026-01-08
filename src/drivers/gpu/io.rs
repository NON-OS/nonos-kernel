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

#[inline(always)]
pub fn outw(port: u16, val: u16) {
    // SAFETY: VBE I/O ports are valid for GPU register access
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nostack, preserves_flags)
        );
    }
}

#[inline(always)]
pub fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: VBE I/O ports are valid for GPU register access
    unsafe {
        asm!(
            "in ax, dx",
            in("dx") port,
            out("ax") val,
            options(nostack, preserves_flags)
        );
    }
    val
}

#[inline(always)]
pub fn outb(port: u16, val: u8) {
    // SAFETY: I/O port access is valid in kernel mode
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, preserves_flags)
        );
    }
}

#[inline(always)]
pub fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: I/O port access is valid in kernel mode
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, preserves_flags)
        );
    }
    val
}
