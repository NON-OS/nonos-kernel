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

#[inline]
pub fn enable_write_protection() {
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr0", "or {tmp:e}, 0x10000", "mov cr0, {tmp}",
            tmp = out(reg) _, options(nostack, preserves_flags)
        );
    }
}

#[inline]
pub unsafe fn disable_write_protection() {
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr0", "and {tmp:e}, 0xFFFEFFFF", "mov cr0, {tmp}",
            tmp = out(reg) _, options(nostack, preserves_flags)
        );
    }
}

#[inline]
pub unsafe fn with_write_protection_disabled<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    unsafe {
        disable_write_protection();
        let result = f();
        enable_write_protection();
        result
    }
}
