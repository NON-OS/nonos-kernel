// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::ptr;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::{frame_alloc, layout, virt};
use super::super::constants::PAGE_SIZE;
use super::super::error::{BuddyAllocError, BuddyAllocResult};
use super::super::stats::ALLOCATION_STATS;
use super::super::types::AllocStats;
use super::core::VmapAllocator;

static VMAP_ALLOCATOR: Mutex<VmapAllocator> = Mutex::new(VmapAllocator::new());

pub fn init() -> BuddyAllocResult<()> { VMAP_ALLOCATOR.lock().init() }

pub fn allocate_pages(count: usize) -> BuddyAllocResult<VirtAddr> {
    if count == 0 { return Err(BuddyAllocError::InvalidPageCount); }
    let size = count * PAGE_SIZE;
    let virt_addr = VMAP_ALLOCATOR.lock().allocate_range(size, PAGE_SIZE)?;
    for i in 0..count {
        let page_addr = VirtAddr::new(virt_addr.as_u64() + (i * PAGE_SIZE) as u64);
        let phys_addr = frame_alloc::allocate_frame().ok_or(BuddyAllocError::FrameAllocationFailed)?;
        map_page(page_addr, phys_addr)?;
    }
    unsafe { ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, size); }
    Ok(virt_addr)
}

pub fn free_pages(addr: VirtAddr, count: usize) -> BuddyAllocResult<()> {
    if count == 0 { return Err(BuddyAllocError::InvalidPageCount); }
    for i in 0..count {
        if let Some(phys_addr) = unmap_page(VirtAddr::new(addr.as_u64() + (i * PAGE_SIZE) as u64))? {
            let _ = frame_alloc::deallocate_frame(phys_addr);
        }
    }
    VMAP_ALLOCATOR.lock().deallocate_range(addr)
}

pub fn allocate_aligned(size: usize, align: usize) -> BuddyAllocResult<VirtAddr> {
    if size == 0 || align == 0 || !align.is_power_of_two() { return Err(BuddyAllocError::InvalidAlignment); }
    let page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let total_size = page_count * PAGE_SIZE;
    let virt_addr = VMAP_ALLOCATOR.lock().allocate_range(total_size, align)?;
    for i in 0..page_count {
        let page_addr = VirtAddr::new(virt_addr.as_u64() + (i * PAGE_SIZE) as u64);
        map_page(page_addr, frame_alloc::allocate_frame().ok_or(BuddyAllocError::FrameAllocationFailed)?)?;
    }
    unsafe { ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, total_size); }
    Ok(virt_addr)
}

pub fn free_aligned(addr: VirtAddr, size: usize) -> BuddyAllocResult<()> { free_pages(addr, (size + PAGE_SIZE - 1) / PAGE_SIZE) }
pub fn deallocate_pages(addr: VirtAddr, count: usize) -> BuddyAllocResult<()> { if count == 0 { return Err(BuddyAllocError::InvalidPageCount); } for i in 0..count { unmap_page(VirtAddr::new(addr.as_u64() + (i * PAGE_SIZE) as u64))?; } VMAP_ALLOCATOR.lock().deallocate_range(addr) }
pub fn deallocate_aligned(addr: VirtAddr, size: usize) -> BuddyAllocResult<()> { deallocate_pages(addr, (size + PAGE_SIZE - 1) / PAGE_SIZE) }
pub fn get_allocation_stats() -> AllocStats { ALLOCATION_STATS.get_stats(VMAP_ALLOCATOR.lock().allocated_count()) }
pub fn is_valid_allocation(addr: VirtAddr) -> bool { VMAP_ALLOCATOR.lock().is_allocated(addr.as_u64()) }
pub fn get_allocation_size(addr: VirtAddr) -> Option<usize> { VMAP_ALLOCATOR.lock().get_size(addr.as_u64()) }
pub fn validate_range(addr: VirtAddr, size: usize) -> bool { let a = addr.as_u64(); if a < layout::VMAP_BASE || a + size as u64 > layout::VMAP_BASE + layout::VMAP_SIZE { return false; } VMAP_ALLOCATOR.lock().get_size(a).map(|s| size <= s).unwrap_or(false) }
#[inline] pub fn total_allocated() -> u64 { ALLOCATION_STATS.total_allocated() }
#[inline] pub fn peak_allocated() -> u64 { ALLOCATION_STATS.peak_allocated() }
fn map_page(virt_addr: VirtAddr, phys_addr: PhysAddr) -> BuddyAllocResult<()> { virt::map_page_4k(virt_addr, phys_addr, true, true, false).map_err(|_| BuddyAllocError::MappingFailed) }
fn unmap_page(virt_addr: VirtAddr) -> BuddyAllocResult<Option<PhysAddr>> { let pa = virt::translate_addr(virt_addr).map_err(|_| BuddyAllocError::TranslationFailed)?; virt::unmap_page(virt_addr).map_err(|_| BuddyAllocError::UnmapFailed)?; Ok(Some(pa)) }
