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

extern crate alloc;
use super::super::constants::DMA_VADDR_BASE;
use super::super::error::DmaResult;
use super::super::types::{DmaRegion, StreamingMapping};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use crate::memory::addr::VirtAddr;

pub struct DmaAllocator {
    pub(super) coherent_regions: BTreeMap<VirtAddr, DmaRegion>,
    pub(super) streaming_mappings: BTreeMap<u64, StreamingMapping>,
    pub(super) next_vaddr: u64,
    pub(super) next_mapping_id: u64,
    pub(super) initialized: bool,
    pub(super) free_ranges: Vec<(u64, usize)>,
}

impl DmaAllocator {
    pub const fn new() -> Self {
        Self {
            coherent_regions: BTreeMap::new(),
            streaming_mappings: BTreeMap::new(),
            next_vaddr: DMA_VADDR_BASE,
            next_mapping_id: 1,
            initialized: false,
            free_ranges: Vec::new(),
        }
    }

    pub fn init(&mut self) -> DmaResult<()> {
        if self.initialized {
            return Ok(());
        }
        self.next_vaddr = DMA_VADDR_BASE;
        self.coherent_regions.clear();
        self.streaming_mappings.clear();
        self.next_mapping_id = 1;
        self.free_ranges.clear();
        self.initialized = true;
        Ok(())
    }

    pub(super) fn reclaim_virtual_range(&mut self, addr: u64, size: usize) {
        self.free_ranges.push((addr, size));
    }

    pub(super) fn try_reuse_virtual_range(&mut self, size: usize) -> Option<u64> {
        for i in 0..self.free_ranges.len() {
            if self.free_ranges[i].1 >= size {
                let (addr, range_size) = self.free_ranges[i];
                if range_size == size {
                    self.free_ranges.swap_remove(i);
                } else {
                    self.free_ranges[i] = (addr + size as u64, range_size - size);
                }
                return Some(addr);
            }
        }
        None
    }

    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for DmaAllocator {
    fn default() -> Self {
        Self::new()
    }
}
