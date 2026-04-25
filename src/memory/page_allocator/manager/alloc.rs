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

use super::super::constants::{MAX_ALLOCATION_SIZE, MAX_TRACKED_PAGES, ZERO_PATTERN};
use super::super::error::{PageAllocError, PageAllocResult};
use super::super::types::AllocatedPage;
use super::allocator::PageAllocator;
use super::globals::{get_timestamp, ALLOCATOR_STATS};
use super::mapping::{allocate_virtual_pages, get_physical_address};
use crate::memory::layout;
use x86_64::VirtAddr;

impl PageAllocator {
    pub(super) fn allocate_page(&mut self, size: usize) -> PageAllocResult<VirtAddr> {
        if !self.initialized {
            return Err(PageAllocError::NotInitialized);
        }
        if size == 0 || size > MAX_ALLOCATION_SIZE {
            return Err(PageAllocError::InvalidSize);
        }
        if self.allocated_pages.len() >= MAX_TRACKED_PAGES {
            return Err(PageAllocError::TooManyPages);
        }
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        let total_size = page_count * layout::PAGE_SIZE;
        let va = allocate_virtual_pages(page_count)?;
        let pa = get_physical_address(va)?;
        let page_id = self.next_page_id;
        self.next_page_id += 1;
        let allocated_page = AllocatedPage {
            page_id,
            virtual_addr: va,
            physical_addr: pa,
            allocation_time: get_timestamp(),
            size: total_size,
        };
        self.allocated_pages.push(allocated_page);
        ALLOCATOR_STATS.record_allocation(total_size);
        unsafe {
            core::ptr::write_bytes(va.as_mut_ptr::<u8>(), ZERO_PATTERN, total_size);
        }
        Ok(va)
    }
}
