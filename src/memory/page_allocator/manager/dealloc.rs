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

use super::super::constants::ZERO_PATTERN;
use super::super::error::{PageAllocError, PageAllocResult};
use super::allocator::PageAllocator;
use super::globals::ALLOCATOR_STATS;
use super::mapping::free_virtual_pages;
use crate::memory::addr::VirtAddr;
use crate::memory::layout;

impl PageAllocator {
    pub(super) fn deallocate_page(&mut self, va: VirtAddr) -> PageAllocResult<()> {
        let page_idx = self
            .allocated_pages
            .iter()
            .position(|p| p.virtual_addr == va)
            .ok_or(PageAllocError::PageNotFound)?;
        let page = self.allocated_pages.remove(page_idx);
        unsafe {
            core::ptr::write_bytes(va.as_mut_ptr::<u8>(), ZERO_PATTERN, page.size);
        }
        free_virtual_pages(va, page.size / layout::PAGE_SIZE)?;
        ALLOCATOR_STATS.record_deallocation(page.size);
        Ok(())
    }
}
