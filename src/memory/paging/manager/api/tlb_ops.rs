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

use super::globals::PAGING_STATS;
use crate::memory::paging::error::PagingResult;
use crate::memory::paging::tlb;
use x86_64::{PhysAddr, VirtAddr};

pub fn flush_tlb(virtual_addr: Option<VirtAddr>) -> PagingResult<()> {
    PAGING_STATS.record_tlb_flush();
    match virtual_addr {
        Some(addr) => tlb::invalidate_page(addr),
        None => tlb::invalidate_all(),
    }
    Ok(())
}

pub fn invalidate_page(va: VirtAddr) {
    tlb::invalidate_page(va);
    PAGING_STATS.record_tlb_flush();
}

pub fn invalidate_all_pages() {
    tlb::invalidate_all();
    PAGING_STATS.record_tlb_flush();
}

pub fn get_current_cr3() -> PhysAddr {
    tlb::get_cr3()
}

pub fn set_cr3(page_table_pa: PhysAddr) {
    tlb::set_cr3(page_table_pa);
}

pub fn enable_write_protection() {
    tlb::enable_write_protection();
}

pub unsafe fn disable_write_protection() {
    unsafe {
        tlb::disable_write_protection();
    }
}
