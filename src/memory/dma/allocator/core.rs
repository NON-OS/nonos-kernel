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
use alloc::collections::BTreeMap;
use x86_64::VirtAddr;
use super::super::constants::DMA_VADDR_BASE;
use super::super::error::DmaResult;
use super::super::types::{DmaRegion, StreamingMapping};

pub struct DmaAllocator {
    pub(super) coherent_regions: BTreeMap<VirtAddr, DmaRegion>,
    pub(super) streaming_mappings: BTreeMap<u64, StreamingMapping>,
    pub(super) next_vaddr: u64,
    pub(super) next_mapping_id: u64,
    pub(super) initialized: bool,
}

impl DmaAllocator {
    pub const fn new() -> Self {
        Self { coherent_regions: BTreeMap::new(), streaming_mappings: BTreeMap::new(), next_vaddr: DMA_VADDR_BASE, next_mapping_id: 1, initialized: false }
    }

    pub fn init(&mut self) -> DmaResult<()> {
        if self.initialized { return Ok(()); }
        self.next_vaddr = DMA_VADDR_BASE;
        self.coherent_regions.clear();
        self.streaming_mappings.clear();
        self.next_mapping_id = 1;
        self.initialized = true;
        Ok(())
    }

    pub const fn is_initialized(&self) -> bool { self.initialized }
}

impl Default for DmaAllocator {
    fn default() -> Self { Self::new() }
}
