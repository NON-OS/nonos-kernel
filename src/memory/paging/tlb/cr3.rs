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

use crate::memory::addr::PhysAddr;

#[inline]
pub fn flush_address_space(cr3_value: PhysAddr) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) cr3_value.as_u64(), options(nostack, preserves_flags));
    }
}

#[inline]
pub fn get_cr3() -> PhysAddr {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    PhysAddr::new(cr3 & !0xFFF)
}

#[inline]
pub fn set_cr3(page_table_pa: PhysAddr) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) page_table_pa.as_u64(), options(nostack, preserves_flags));
    }
}
