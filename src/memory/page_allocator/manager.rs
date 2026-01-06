// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::{layout, frame_alloc, virt};
use super::constants::*;
use super::error::{PageAllocError, PageAllocResult};
use super::types::*;
static PAGE_ALLOCATOR: Mutex<PageAllocator> = Mutex::new(PageAllocator::new());
static ALLOCATOR_STATS: AllocatorStats = AllocatorStats::new();
struct PageAllocator {
    allocated_pages: Vec<AllocatedPage>,
    next_page_id: u64,
    initialized: bool,
}

impl PageAllocator {
    const fn new() -> Self {
        Self { allocated_pages: Vec::new(), next_page_id: INITIAL_PAGE_ID, initialized: false }
    }

    fn init(&mut self) -> PageAllocResult<()> {
        if self.initialized { return Ok(()); }
        self.allocated_pages.clear();
        self.next_page_id = INITIAL_PAGE_ID;
        self.initialized = true;
        Ok(())
    }

    fn allocate_page(&mut self, size: usize) -> PageAllocResult<VirtAddr> {
        if !self.initialized { return Err(PageAllocError::NotInitialized); }
        if size == 0 || size > MAX_ALLOCATION_SIZE { return Err(PageAllocError::InvalidSize); }
        if self.allocated_pages.len() >= MAX_TRACKED_PAGES { return Err(PageAllocError::TooManyPages); }
        let page_count = (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
        let total_size = page_count * layout::PAGE_SIZE;
        let va = self.allocate_virtual_pages(page_count)?;
        let pa = self.get_physical_address(va)?;
        let page_id = self.next_page_id;
        self.next_page_id += 1;
        let allocated_page = AllocatedPage { page_id, virtual_addr: va, physical_addr: pa, allocation_time: get_timestamp(), size: total_size };
        self.allocated_pages.push(allocated_page);
        ALLOCATOR_STATS.record_allocation(total_size);

        // SAFETY: va is valid virtual address we just allocated, total_size is exact allocation size
        unsafe { core::ptr::write_bytes(va.as_mut_ptr::<u8>(), ZERO_PATTERN, total_size); }
        Ok(va)
    }

    fn deallocate_page(&mut self, va: VirtAddr) -> PageAllocResult<()> {
        let page_idx = self.allocated_pages.iter().position(|p| p.virtual_addr == va).ok_or(PageAllocError::PageNotFound)?;
        let page = self.allocated_pages.remove(page_idx);

        // SAFETY: va is valid virtual address that we allocated, page.size is exact allocation size
        unsafe { core::ptr::write_bytes(va.as_mut_ptr::<u8>(), ZERO_PATTERN, page.size); }
        self.free_virtual_pages(va, page.size / layout::PAGE_SIZE)?;
        ALLOCATOR_STATS.record_deallocation(page.size);
        Ok(())
    }

    fn get_page_info(&self, va: VirtAddr) -> Option<&AllocatedPage> {
        self.allocated_pages.iter().find(|p| p.virtual_addr == va)
    }

    fn allocate_virtual_pages(&self, page_count: usize) -> PageAllocResult<VirtAddr> {
        let mut allocated_frames = Vec::new();
        for _ in 0..page_count {
            let frame = frame_alloc::allocate_frame().ok_or(PageAllocError::FrameAllocationFailed)?;
            allocated_frames.push(frame);
        }

        let first_frame = allocated_frames[0];
        let va = VirtAddr::new(layout::VMAP_BASE + first_frame.as_u64());
        for (i, frame) in allocated_frames.iter().enumerate() {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            self.map_page(page_va, *frame)?;
        }
        Ok(va)
    }

    fn free_virtual_pages(&self, va: VirtAddr, page_count: usize) -> PageAllocResult<()> {
        for i in 0..page_count {
            let page_va = VirtAddr::new(va.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let pa = self.get_physical_address(page_va)?;
            self.unmap_page(page_va)?;
            let _ = frame_alloc::deallocate_frame(pa);
        }
        Ok(())
    }

    fn map_page(&self, va: VirtAddr, pa: PhysAddr) -> PageAllocResult<()> {
        virt::map_page_4k(va, pa, true, false, false).map_err(|_| PageAllocError::MappingFailed)
    }

    fn unmap_page(&self, va: VirtAddr) -> PageAllocResult<()> {
        virt::unmap_page(va).map_err(|_| PageAllocError::UnmapFailed)
    }

    fn get_physical_address(&self, va: VirtAddr) -> PageAllocResult<PhysAddr> {
        virt::translate_addr(va).map_err(|_| PageAllocError::TranslationFailed)
    }

    fn get_allocator_stats(&self) -> PageAllocatorStats {
        PageAllocatorStats {
            total_allocations: ALLOCATOR_STATS.total_allocations.load(Ordering::Relaxed),
            total_deallocations: ALLOCATOR_STATS.total_deallocations.load(Ordering::Relaxed),
            active_pages: ALLOCATOR_STATS.active_pages.load(Ordering::Relaxed),
            bytes_allocated: ALLOCATOR_STATS.bytes_allocated.load(Ordering::Relaxed),
            peak_pages: ALLOCATOR_STATS.peak_pages.load(Ordering::Relaxed),
            allocated_pages: self.allocated_pages.len(),
        }
    }
}

fn get_timestamp() -> u64 {
    // SAFETY: RDTSC is safe read-only instruction
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn init() -> PageAllocResult<()> { PAGE_ALLOCATOR.lock().init() }
pub fn allocate_page() -> PageAllocResult<VirtAddr> { PAGE_ALLOCATOR.lock().allocate_page(layout::PAGE_SIZE) }
pub fn allocate_pages(count: usize) -> PageAllocResult<VirtAddr> { PAGE_ALLOCATOR.lock().allocate_page(count * layout::PAGE_SIZE) }
pub fn allocate_sized(size: usize) -> PageAllocResult<VirtAddr> { PAGE_ALLOCATOR.lock().allocate_page(size) }
pub fn deallocate_page(va: VirtAddr) -> PageAllocResult<()> { PAGE_ALLOCATOR.lock().deallocate_page(va) }
pub fn get_page_info(va: VirtAddr) -> Option<PageInfo> {
    PAGE_ALLOCATOR.lock().get_page_info(va).map(|p| PageInfo {
        page_id: p.page_id, virtual_addr: p.virtual_addr, physical_addr: p.physical_addr,
        allocation_time: p.allocation_time, size: p.size,
    })
}

pub fn get_stats() -> PageAllocatorStats { PAGE_ALLOCATOR.lock().get_allocator_stats() }
pub fn is_allocated(va: VirtAddr) -> bool { PAGE_ALLOCATOR.lock().get_page_info(va).is_some() }
pub fn get_allocation_count() -> usize { ALLOCATOR_STATS.active_pages.load(Ordering::Relaxed) }
pub fn get_total_bytes_allocated() -> u64 { ALLOCATOR_STATS.bytes_allocated.load(Ordering::Relaxed) }
pub fn get_peak_pages() -> usize { ALLOCATOR_STATS.peak_pages.load(Ordering::Relaxed) }
pub fn is_initialized() -> bool { PAGE_ALLOCATOR.lock().initialized }
