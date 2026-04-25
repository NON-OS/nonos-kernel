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
use super::mapping::map_page;
use super::stats::VMAP_ALLOCATOR;
use crate::memory::frame_alloc;
use core::ptr;
use x86_64::VirtAddr;

pub fn allocate_pages(count: usize) -> BuddyAllocResult<VirtAddr> {
    if count == 0 {
        return Err(BuddyAllocError::InvalidPageCount);
    }
    let size = count.checked_mul(PAGE_SIZE).ok_or(BuddyAllocError::Overflow)?;
    let virt_addr = VMAP_ALLOCATOR.lock().allocate_range(size, PAGE_SIZE)?;
    for i in 0..count {
        let offset = i.checked_mul(PAGE_SIZE).ok_or(BuddyAllocError::Overflow)?;
        let page_addr = VirtAddr::new(virt_addr.as_u64() + offset as u64);
        let phys = frame_alloc::allocate_frame().ok_or(BuddyAllocError::FrameAllocationFailed)?;
        map_page(page_addr, phys)?;
    }
    unsafe {
        ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, size);
    }
    Ok(virt_addr)
}

pub fn allocate_aligned(size: usize, align: usize) -> BuddyAllocResult<VirtAddr> {
    if size == 0 || align == 0 || !align.is_power_of_two() {
        return Err(BuddyAllocError::InvalidAlignment);
    }
    let page_count = size.checked_add(PAGE_SIZE - 1).ok_or(BuddyAllocError::Overflow)? / PAGE_SIZE;
    let total_size = page_count.checked_mul(PAGE_SIZE).ok_or(BuddyAllocError::Overflow)?;
    let virt_addr = VMAP_ALLOCATOR.lock().allocate_range(total_size, align)?;
    for i in 0..page_count {
        let offset = i.checked_mul(PAGE_SIZE).ok_or(BuddyAllocError::Overflow)?;
        let page_addr = VirtAddr::new(virt_addr.as_u64() + offset as u64);
        let phys = frame_alloc::allocate_frame().ok_or(BuddyAllocError::FrameAllocationFailed)?;
        map_page(page_addr, phys)?;
    }
    unsafe {
        ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, total_size);
    }
    Ok(virt_addr)
}
