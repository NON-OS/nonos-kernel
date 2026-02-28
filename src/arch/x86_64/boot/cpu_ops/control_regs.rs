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

use core::arch::asm;

#[inline]
pub fn read_cr0() -> u64 {
    let value: u64;
    // SAFETY: Reading CR0 is always valid
    unsafe {
        asm!(
            "mov {}, cr0",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr0(value: u64) {
    // SAFETY: Caller ensures CR0 value is valid
    asm!(
        "mov cr0, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: Reading CR2 is always valid
    unsafe {
        asm!(
            "mov {}, cr2",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: Reading CR3 is always valid
    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr3(value: u64) {
    // SAFETY: Caller ensures page table address is valid
    asm!(
        "mov cr3, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: Reading CR4 is always valid
    unsafe {
        asm!(
            "mov {}, cr4",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr4(value: u64) {
    // SAFETY: Caller ensures CR4 value is valid
    asm!(
        "mov cr4, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub fn read_cr8() -> u64 {
    let value: u64;
    // SAFETY: Reading CR8 is always valid in long mode
    unsafe {
        asm!(
            "mov {}, cr8",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr8(value: u64) {
    // SAFETY: Caller ensures TPR value is valid
    asm!(
        "mov cr8, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}
