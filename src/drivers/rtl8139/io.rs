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


#[inline]
pub fn inb(port: u16) -> u8 {
    // SAFETY: I/O port access for RTL8139 hardware registers
    unsafe {
        let val: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack)
        );
        val
    }
}

#[inline]
pub fn outb(port: u16, value: u8) {
    // SAFETY: I/O port access for RTL8139 hardware registers
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack)
        );
    }
}

#[inline]
pub fn inw(port: u16) -> u16 {
    // SAFETY: I/O port access for RTL8139 hardware registers
    unsafe {
        let val: u16;
        core::arch::asm!(
            "in ax, dx",
            out("ax") val,
            in("dx") port,
            options(nomem, nostack)
        );
        val
    }
}

#[inline]
pub fn outw(port: u16, value: u16) {
    // SAFETY: I/O port access for RTL8139 hardware registers
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack)
        );
    }
}

#[inline]
pub fn inl(port: u16) -> u32 {
    // SAFETY: I/O port access for RTL8139 hardware registers
    unsafe {
        let val: u32;
        core::arch::asm!(
            "in eax, dx",
            out("eax") val,
            in("dx") port,
            options(nomem, nostack)
        );
        val
    }
}

#[inline]
pub fn outl(port: u16, value: u32) {
    // SAFETY: I/O port access for RTL8139 hardware registers
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack)
        );
    }
}
