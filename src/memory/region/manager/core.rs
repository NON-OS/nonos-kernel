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
use super::super::error::RegionResult;
use super::super::stats::RegionStatistics;
use super::super::types::{MemRegion, RegionType};
use crate::memory::layout;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub struct RegionManager {
    pub(super) regions: BTreeMap<u64, MemRegion>,
    pub(super) free_regions: Vec<MemRegion>,
    pub(super) region_pools: BTreeMap<RegionType, Vec<MemRegion>>,
    pub(super) next_region_id: u64,
    pub(super) initialized: bool,
}

impl RegionManager {
    pub const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
            free_regions: Vec::new(),
            region_pools: BTreeMap::new(),
            next_region_id: 1,
            initialized: false,
        }
    }

    pub fn init(&mut self, stats: &RegionStatistics) -> RegionResult<()> {
        if self.initialized {
            return Ok(());
        }
        self.regions.clear();
        self.free_regions.clear();
        self.region_pools.clear();
        self.add_initial_regions(stats)?;
        self.initialized = true;
        Ok(())
    }

    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub(super) fn add_initial_regions(&mut self, stats: &RegionStatistics) -> RegionResult<()> {
        self.add_region(
            MemRegion::new(
                layout::KERNEL_BASE,
                (layout::KDATA_BASE - layout::KERNEL_BASE) as usize,
                RegionType::Kernel,
            ),
            stats,
        )?;
        self.add_region(
            MemRegion::new(layout::KHEAP_BASE, layout::KHEAP_SIZE as usize, RegionType::Heap),
            stats,
        )?;
        self.add_region(
            MemRegion::new(layout::VMAP_BASE, layout::VMAP_SIZE as usize, RegionType::Available),
            stats,
        )?;
        self.add_region(
            MemRegion::new(layout::MMIO_BASE, layout::MMIO_SIZE as usize, RegionType::Mmio),
            stats,
        )?;
        Ok(())
    }
}

impl Default for RegionManager {
    fn default() -> Self {
        Self::new()
    }
}
