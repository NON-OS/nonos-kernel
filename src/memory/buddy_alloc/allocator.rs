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
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use x86_64::VirtAddr;
use crate::memory::layout;
use super::constants::*;
use super::error::{BuddyAllocError, BuddyAllocResult};
use super::stats::ALLOCATION_STATS;
use super::types::{AllocatedBlock, BuddyBlock};

// ============================================================================
// VMAP ALLOCATOR
// ============================================================================
pub struct VmapAllocator {
    free_lists: [Vec<BuddyBlock>; FREE_LIST_COUNT],
    allocated_blocks: BTreeMap<u64, AllocatedBlock>,
    base_addr: u64,
    total_size: u64,
    initialized: bool,
}

impl VmapAllocator {
    pub const fn new() -> Self {
        const INIT: Vec<BuddyBlock> = Vec::new();
        Self {
            free_lists: [INIT; FREE_LIST_COUNT],
            allocated_blocks: BTreeMap::new(),
            base_addr: layout::VMAP_BASE,
            total_size: layout::VMAP_SIZE,
            initialized: false,
        }
    }

    pub fn init(&mut self) -> BuddyAllocResult<()> {
        if self.initialized {
            return Ok(());
        }

        for list in &mut self.free_lists {
            list.clear();
        }
        self.allocated_blocks.clear();
        let initial_order = size_to_order(self.total_size as usize);
        if initial_order <= MAX_ORDER {
            let list_idx = initial_order.saturating_sub(MIN_ORDER);
            if list_idx < self.free_lists.len() {
                self.free_lists[list_idx].push(BuddyBlock {
                    addr: self.base_addr,
                    order: initial_order,
                });
            }
        }

        self.initialized = true;
        Ok(())
    }
    pub fn find_block(&mut self, order: usize) -> Option<BuddyBlock> {
        for current_order in order..=MAX_ORDER {
            let list_idx = current_order.saturating_sub(MIN_ORDER);
            if list_idx >= self.free_lists.len() || self.free_lists[list_idx].is_empty() {
                continue;
            }
            let mut block = self.free_lists[list_idx].remove(0);
            while block.order > order {
                let split_order = block.order - 1;
                let split_size = 1u64 << split_order;
                let buddy_addr = block.addr + split_size;
                let buddy_idx = split_order.saturating_sub(MIN_ORDER);
                if buddy_idx < self.free_lists.len() {
                    self.free_lists[buddy_idx].push(BuddyBlock {
                        addr: buddy_addr,
                        order: split_order,
                    });
                }

                block.order = split_order;

                if block.order == order {
                    break;
                }
            }

            return Some(block);
        }
        None
    }
    pub fn merge_buddies(&mut self, mut block: BuddyBlock) {
        while block.order < MAX_ORDER {
            let buddy_addr = buddy_address(block.addr, block.order);
            let list_idx = block.order.saturating_sub(MIN_ORDER);

            if list_idx >= self.free_lists.len() {
                break;
            }
            let buddy_pos = self.free_lists[list_idx]
                .iter()
                .position(|b| b.addr == buddy_addr);

            if let Some(pos) = buddy_pos {
                self.free_lists[list_idx].remove(pos);
                block = BuddyBlock {
                    addr: block.addr.min(buddy_addr),
                    order: block.order + 1,
                };
            } else {
                break;
            }
        }
        let list_idx = block.order.saturating_sub(MIN_ORDER);
        if list_idx < self.free_lists.len() {
            self.free_lists[list_idx].push(block);
        }
    }
    pub fn allocate_range(&mut self, size: usize, align: usize) -> BuddyAllocResult<VirtAddr> {
        if !self.initialized {
            return Err(BuddyAllocError::NotInitialized);
        }

        if size == 0 {
            return Err(BuddyAllocError::InvalidSize);
        }

        if !align.is_power_of_two() {
            return Err(BuddyAllocError::InvalidAlignment);
        }

        let aligned_size = align_up(size, align.max(PAGE_SIZE));
        let required_order = size_to_order(aligned_size);

        if required_order > MAX_ORDER {
            return Err(BuddyAllocError::AllocationTooLarge);
        }

        if let Some(block) = self.find_block(required_order) {
            if block.addr < self.base_addr
                || block.addr + (1u64 << block.order) > self.base_addr + self.total_size
            {
                return Err(BuddyAllocError::BlockOutOfRange);
            }

            let allocated_block = AllocatedBlock {
                addr: block.addr,
                size: aligned_size,
                order: block.order,
                flags: 0,
            };

            self.allocated_blocks.insert(block.addr, allocated_block);
            ALLOCATION_STATS.record_allocation(aligned_size as u64);

            Ok(VirtAddr::new(block.addr))
        } else {
            Err(BuddyAllocError::OutOfVirtualMemory)
        }
    }
    pub fn deallocate_range(&mut self, addr: VirtAddr) -> BuddyAllocResult<()> {
        let addr_u64 = addr.as_u64();

        if let Some(allocated_block) = self.allocated_blocks.remove(&addr_u64) {
            let block = BuddyBlock {
                addr: allocated_block.addr,
                order: allocated_block.order,
            };

            self.merge_buddies(block);
            ALLOCATION_STATS.record_deallocation(allocated_block.size as u64);

            Ok(())
        } else {
            Err(BuddyAllocError::InvalidAddress)
        }
    }
    pub fn allocated_count(&self) -> usize {
        self.allocated_blocks.len()
    }
    pub fn is_allocated(&self, addr: u64) -> bool {
        self.allocated_blocks.contains_key(&addr)
    }
    pub fn get_size(&self, addr: u64) -> Option<usize> {
        self.allocated_blocks.get(&addr).map(|b| b.size)
    }
}
#[inline]
pub const fn align_up(value: usize, align: usize) -> usize {
    if align == 0 || align & (align - 1) != 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

// ============================================================================
// GLOBAL STATE
// ============================================================================

use core::ptr;
use spin::Mutex;
use x86_64::PhysAddr;
use crate::memory::{frame_alloc, virt};
use super::types::AllocStats;

static VMAP_ALLOCATOR: Mutex<VmapAllocator> = Mutex::new(VmapAllocator::new());

// ============================================================================
// PUBLIC API
// ============================================================================

pub fn init() -> BuddyAllocResult<()> {
    VMAP_ALLOCATOR.lock().init()
}

pub fn allocate_pages(count: usize) -> BuddyAllocResult<VirtAddr> {
    if count == 0 {
        return Err(BuddyAllocError::InvalidPageCount);
    }

    let size = count * PAGE_SIZE;
    let virt_addr = {
        let mut allocator = VMAP_ALLOCATOR.lock();
        allocator.allocate_range(size, PAGE_SIZE)?
    };

    for i in 0..count {
        let page_addr = VirtAddr::new(virt_addr.as_u64() + (i * PAGE_SIZE) as u64);
        let phys_addr =
            frame_alloc::allocate_frame().ok_or(BuddyAllocError::FrameAllocationFailed)?;

        map_page(page_addr, phys_addr)?;
    }

    // SAFETY: Memory is freshly mapped, we have exclusive access
    unsafe {
        ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, size);
    }

    Ok(virt_addr)
}

pub fn free_pages(addr: VirtAddr, count: usize) -> BuddyAllocResult<()> {
    if count == 0 {
        return Err(BuddyAllocError::InvalidPageCount);
    }

    for i in 0..count {
        let page_addr = VirtAddr::new(addr.as_u64() + (i * PAGE_SIZE) as u64);
        if let Some(phys_addr) = unmap_page(page_addr)? {
            frame_alloc::deallocate_frame(phys_addr);
        }
    }

    VMAP_ALLOCATOR.lock().deallocate_range(addr)
}

pub fn allocate_aligned(size: usize, align: usize) -> BuddyAllocResult<VirtAddr> {
    if size == 0 || align == 0 || !align.is_power_of_two() {
        return Err(BuddyAllocError::InvalidAlignment);
    }

    let page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let total_size = page_count * PAGE_SIZE;
    let virt_addr = {
        let mut allocator = VMAP_ALLOCATOR.lock();
        allocator.allocate_range(total_size, align)?
    };

    for i in 0..page_count {
        let page_addr = VirtAddr::new(virt_addr.as_u64() + (i * PAGE_SIZE) as u64);
        let phys_addr =
            frame_alloc::allocate_frame().ok_or(BuddyAllocError::FrameAllocationFailed)?;

        map_page(page_addr, phys_addr)?;
    }

    // SAFETY: Memory is freshly mapped, we have exclusive access
    unsafe {
        ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, total_size);
    }

    Ok(virt_addr)
}

pub fn free_aligned(addr: VirtAddr, size: usize) -> BuddyAllocResult<()> {
    let page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    free_pages(addr, page_count)
}

pub fn deallocate_pages(addr: VirtAddr, count: usize) -> BuddyAllocResult<()> {
    if count == 0 {
        return Err(BuddyAllocError::InvalidPageCount);
    }

    for i in 0..count {
        let page_addr = VirtAddr::new(addr.as_u64() + (i * PAGE_SIZE) as u64);
        unmap_page(page_addr)?;
    }

    VMAP_ALLOCATOR.lock().deallocate_range(addr)
}

pub fn deallocate_aligned(addr: VirtAddr, size: usize) -> BuddyAllocResult<()> {
    let page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    deallocate_pages(addr, page_count)
}

pub fn get_allocation_stats() -> AllocStats {
    ALLOCATION_STATS.get_stats(VMAP_ALLOCATOR.lock().allocated_count())
}

pub fn is_valid_allocation(addr: VirtAddr) -> bool {
    VMAP_ALLOCATOR.lock().is_allocated(addr.as_u64())
}

pub fn get_allocation_size(addr: VirtAddr) -> Option<usize> {
    VMAP_ALLOCATOR.lock().get_size(addr.as_u64())
}

pub fn validate_range(addr: VirtAddr, size: usize) -> bool {
    let addr_u64 = addr.as_u64();
    if addr_u64 < layout::VMAP_BASE || addr_u64 + size as u64 > layout::VMAP_BASE + layout::VMAP_SIZE
    {
        return false;
    }

    VMAP_ALLOCATOR
        .lock()
        .get_size(addr_u64)
        .map(|alloc_size| size <= alloc_size)
        .unwrap_or(false)
}

#[inline]
pub fn total_allocated() -> u64 {
    ALLOCATION_STATS.total_allocated()
}

#[inline]
pub fn peak_allocated() -> u64 {
    ALLOCATION_STATS.peak_allocated()
}

fn map_page(virt_addr: VirtAddr, phys_addr: PhysAddr) -> BuddyAllocResult<()> {
    virt::map_page_4k(virt_addr, phys_addr, true, true, false)
        .map_err(|_| BuddyAllocError::MappingFailed)
}

fn unmap_page(virt_addr: VirtAddr) -> BuddyAllocResult<Option<PhysAddr>> {
    let phys_addr =
        virt::translate_addr(virt_addr).map_err(|_| BuddyAllocError::TranslationFailed)?;
    virt::unmap_page(virt_addr).map_err(|_| BuddyAllocError::UnmapFailed)?;
    Ok(Some(phys_addr))
}
