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

use super::super::super::constants::PAGE_SIZE;
use super::super::super::error::{BuddyAllocError, BuddyAllocResult};
use super::mapping::unmap_page;
use super::stats::VMAP_ALLOCATOR;
use crate::memory::frame_alloc;
use x86_64::VirtAddr;

pub fn free_pages(addr: VirtAddr, count: usize) -> BuddyAllocResult<()> {
    if count == 0 {
        return Err(BuddyAllocError::InvalidPageCount);
    }
    for i in 0..count {
        let offset = i.checked_mul(PAGE_SIZE).ok_or(BuddyAllocError::Overflow)?;
        let page_addr = VirtAddr::new(addr.as_u64() + offset as u64);
        if let Some(phys_addr) = unmap_page(page_addr)? {
            let _ = frame_alloc::deallocate_frame(phys_addr);
        }
    }
    VMAP_ALLOCATOR.lock().deallocate_range(addr)
}

pub fn free_aligned(addr: VirtAddr, size: usize) -> BuddyAllocResult<()> {
    let page_count = size.checked_add(PAGE_SIZE - 1).ok_or(BuddyAllocError::Overflow)? / PAGE_SIZE;
    free_pages(addr, page_count)
}

pub fn deallocate_pages(addr: VirtAddr, count: usize) -> BuddyAllocResult<()> {
    if count == 0 {
        return Err(BuddyAllocError::InvalidPageCount);
    }
    for i in 0..count {
        let offset = i.checked_mul(PAGE_SIZE).ok_or(BuddyAllocError::Overflow)?;
        let page_addr = VirtAddr::new(addr.as_u64() + offset as u64);
        unmap_page(page_addr)?;
    }
    VMAP_ALLOCATOR.lock().deallocate_range(addr)
}

pub fn deallocate_aligned(addr: VirtAddr, size: usize) -> BuddyAllocResult<()> {
    let page_count = size.checked_add(PAGE_SIZE - 1).ok_or(BuddyAllocError::Overflow)? / PAGE_SIZE;
    deallocate_pages(addr, page_count)
}
