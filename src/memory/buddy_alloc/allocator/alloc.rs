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

use x86_64::VirtAddr;
use super::super::constants::{size_to_order, MAX_ORDER, PAGE_SIZE};
use super::super::error::{BuddyAllocError, BuddyAllocResult};
use super::super::stats::ALLOCATION_STATS;
use super::super::types::{AllocatedBlock, BuddyBlock};
use super::core::VmapAllocator;
use super::utils::align_up;

impl VmapAllocator {
    pub fn allocate_range(&mut self, size: usize, align: usize) -> BuddyAllocResult<VirtAddr> {
        if !self.initialized { return Err(BuddyAllocError::NotInitialized); }
        if size == 0 { return Err(BuddyAllocError::InvalidSize); }
        if !align.is_power_of_two() { return Err(BuddyAllocError::InvalidAlignment); }
        let aligned_size = align_up(size, align.max(PAGE_SIZE));
        let required_order = size_to_order(aligned_size);
        if required_order > MAX_ORDER { return Err(BuddyAllocError::AllocationTooLarge); }
        if let Some(block) = self.find_block(required_order) {
            let block_size = (1u64).checked_shl(block.order as u32).ok_or(BuddyAllocError::Overflow)?;
            let block_end = block.addr.checked_add(block_size).ok_or(BuddyAllocError::Overflow)?;
            let region_end = self.base_addr.checked_add(self.total_size).ok_or(BuddyAllocError::Overflow)?;
            if block.addr < self.base_addr || block_end > region_end {
                return Err(BuddyAllocError::BlockOutOfRange);
            }
            self.allocated_blocks.insert(block.addr, AllocatedBlock { addr: block.addr, size: aligned_size, order: block.order, flags: 0 });
            ALLOCATION_STATS.record_allocation(aligned_size as u64);
            Ok(VirtAddr::new(block.addr))
        } else { Err(BuddyAllocError::OutOfVirtualMemory) }
    }

    pub fn deallocate_range(&mut self, addr: VirtAddr) -> BuddyAllocResult<()> {
        let addr_u64 = addr.as_u64();
        if let Some(allocated_block) = self.allocated_blocks.remove(&addr_u64) {
            self.merge_buddies(BuddyBlock { addr: allocated_block.addr, order: allocated_block.order });
            ALLOCATION_STATS.record_deallocation(allocated_block.size as u64);
            Ok(())
        } else { Err(BuddyAllocError::InvalidAddress) }
    }
}
