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

use super::value_trait::PortValue;

impl PortValue for u32 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u32;
        core::arch::asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insd", in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _, inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsd", in("dx") port,
            inout("rsi") buffer.as_ptr() => _, inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize {
        4
    }
}
