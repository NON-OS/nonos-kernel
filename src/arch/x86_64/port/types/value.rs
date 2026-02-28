// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

pub trait PortValue: Copy + Default {
    // SAFETY: Reading from I/O ports can have side effects on hardware
    unsafe fn read_from_port(port: u16) -> Self;

    // SAFETY: Writing to I/O ports can have side effects on hardware
    unsafe fn write_to_port(port: u16, value: Self);

    // SAFETY: Reading from I/O ports can have side effects on hardware
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]);

    // SAFETY: Writing to I/O ports can have side effects on hardware
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]);

    fn size() -> usize;
}

impl PortValue for u8 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insb",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsb",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize { 1 }
}

impl PortValue for u16 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u16;
        core::arch::asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insw",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsw",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize { 2 }
}

impl PortValue for u32 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u32;
        core::arch::asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insd",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsd",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize { 4 }
}
