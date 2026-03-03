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

#[inline(always)]
pub unsafe fn outl(port: u16, value: u32) { unsafe {
    // SAFETY: caller ensures port access is valid
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, preserves_flags));
}}

#[inline(always)]
pub unsafe fn inl(port: u16) -> u32 { unsafe {
    // SAFETY: caller ensures port access is valid
    let value: u32;
    core::arch::asm!("in eax, dx", in("dx") port, out("eax") value, options(nostack, preserves_flags));
    value
}}
