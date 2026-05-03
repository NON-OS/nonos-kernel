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

use crate::memory::addr::VirtAddr;
use crate::memory::paging::constants::PAGE_SIZE_4K;

#[inline]
pub fn invalidate_page(va: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) va.as_u64(), options(nostack, preserves_flags));
    }
}

#[inline]
pub fn invalidate_all() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

pub fn invalidate_range(start: VirtAddr, page_count: usize) {
    if page_count > 32 {
        invalidate_all();
        return;
    }
    for i in 0..page_count {
        let addr = VirtAddr::new(start.as_u64() + (i * PAGE_SIZE_4K) as u64);
        invalidate_page(addr);
    }
}
