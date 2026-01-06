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
use super::constants::align_size;
use super::error::{RegionError, RegionResult};
use super::stats::RegionStatistics;
use super::types::{get_timestamp, MemRegion, RegionFlags, RegionStats, RegionType};
use crate::memory::layout;
pub struct RegionManager {
    regions: BTreeMap<u64, MemRegion>,
    free_regions: Vec<MemRegion>,
    region_pools: BTreeMap<RegionType, Vec<MemRegion>>,
    next_region_id: u64,
    initialized: bool,
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
    fn add_initial_regions(&mut self, stats: &RegionStatistics) -> RegionResult<()> {
        let kernel_region = MemRegion::new(
            layout::KERNEL_BASE,
            (layout::KDATA_BASE - layout::KERNEL_BASE) as usize,
            RegionType::Kernel,
        );
        self.add_region(kernel_region, stats)?;
        let heap_region = MemRegion::new(
            layout::KHEAP_BASE,
            layout::KHEAP_SIZE as usize,
            RegionType::Heap,
        );
        self.add_region(heap_region, stats)?;
        let vmap_region = MemRegion::new(
            layout::VMAP_BASE,
            layout::VMAP_SIZE as usize,
            RegionType::Available,
        );
        self.add_region(vmap_region, stats)?;
        let mmio_region = MemRegion::new(
            layout::MMIO_BASE,
            layout::MMIO_SIZE as usize,
            RegionType::Mmio,
        );
        self.add_region(mmio_region, stats)?;
        Ok(())
    }
    // ========================================================================
    // REGION MANAGEMENT
    // ========================================================================
    pub fn add_region(
        &mut self,
        mut region: MemRegion,
        stats: &RegionStatistics,
    ) -> RegionResult<u64> {
        let region_id = self.next_region_id;
        self.next_region_id += 1;
        region.creation_time = get_timestamp();
        if self.has_overlap(&region) {
            return Err(RegionError::Overlapping);
        }

        let is_free = region.region_type == RegionType::Available;
        stats.add_region(region.size as u64, is_free);
        self.regions.insert(region_id, region);
        if is_free {
            self.free_regions.push(region);
        }

        let pool = self
            .region_pools
            .entry(region.region_type)
            .or_insert_with(Vec::new);
        pool.push(region);

        Ok(region_id)
    }

    pub fn remove_region(
        &mut self,
        region_id: u64,
        stats: &RegionStatistics,
    ) -> RegionResult<MemRegion> {
        let region = self.regions.remove(&region_id).ok_or(RegionError::NotFound)?;
        let is_free = region.region_type == RegionType::Available;
        stats.remove_region(region.size as u64, is_free);
        if is_free {
            self.free_regions.retain(|r| r.start != region.start);
        }

        if let Some(pool) = self.region_pools.get_mut(&region.region_type) {
            pool.retain(|r| r.start != region.start);
        }

        Ok(region)
    }

    pub fn allocate_region(
        &mut self,
        size: usize,
        region_type: RegionType,
        align: u64,
        stats: &RegionStatistics,
    ) -> RegionResult<MemRegion> {
        let aligned_size = align_size(size, align as usize);
        for (i, region) in self.free_regions.iter().enumerate() {
            let aligned_start = (region.start + align - 1) & !(align - 1);
            let available_size = region.end().saturating_sub(aligned_start);
            if available_size >= aligned_size as u64 {
                let mut allocated = MemRegion::new(aligned_start, aligned_size, region_type);
                allocated.creation_time = get_timestamp();
                let remaining_region = *region;
                self.free_regions.remove(i);
                let fragments = remaining_region.subtract(&allocated);
                for fragment in fragments.iter().flatten() {
                    self.free_regions.push(*fragment);
                }

                let region_id = self.next_region_id;
                self.next_region_id += 1;
                self.regions.insert(region_id, allocated);
                stats.record_allocation(aligned_size as u64);
                return Ok(allocated);
            }
        }

        Err(RegionError::NoFreeRegion)
    }

    pub fn deallocate_region(
        &mut self,
        region: MemRegion,
        stats: &RegionStatistics,
    ) -> RegionResult<()> {
        let available_region = MemRegion::new(region.start, region.size, RegionType::Available);
        self.free_regions.push(available_region);
        self.merge_adjacent_free_regions(stats);
        stats.record_deallocation(region.size as u64);
        Ok(())
    }

    pub fn merge_adjacent_free_regions(&mut self, stats: &RegionStatistics) {
        self.free_regions.sort_by_key(|r| r.start);
        let mut merged_regions = Vec::new();
        let mut current_region: Option<MemRegion> = None;
        for region in self.free_regions.drain(..) {
            match current_region.as_mut() {
                Some(current) => {
                    if let Some(merged) = current.union(&region) {
                        *current = merged;
                        stats.record_merge();
                    } else {
                        merged_regions.push(*current);
                        *current = region;
                    }
                }
                None => {
                    current_region = Some(region);
                }
            }
        }

        if let Some(region) = current_region {
            merged_regions.push(region);
        }

        self.free_regions = merged_regions;
    }

    pub fn split_region(
        &mut self,
        region_id: u64,
        offset: usize,
        stats: &RegionStatistics,
    ) -> RegionResult<(MemRegion, MemRegion)> {
        let region = self.regions.get(&region_id).ok_or(RegionError::NotFound)?.clone();
        if offset >= region.size {
            return Err(RegionError::InvalidSplitOffset);
        }

        let first_part = MemRegion::new(region.start, offset, region.region_type);
        let second_part = MemRegion::new(
            region.start + offset as u64,
            region.size - offset,
            region.region_type,
        );

        self.regions.remove(&region_id);
        let first_id = self.next_region_id;
        self.next_region_id += 1;
        let second_id = self.next_region_id;
        self.next_region_id += 1;
        self.regions.insert(first_id, first_part);
        self.regions.insert(second_id, second_part);
        stats.record_split();
        Ok((first_part, second_part))
    }
    // ========================================================================
    // QUERY METHODS
    // ========================================================================
    pub fn find_region_by_address(&self, addr: u64) -> Option<&MemRegion> {
        self.regions.values().find(|r| r.contains(addr))
    }

    pub fn find_regions_by_type(&self, region_type: RegionType) -> Vec<MemRegion> {
        self.region_pools
            .get(&region_type)
            .cloned()
            .unwrap_or_default()
    }

    pub fn has_overlap(&self, region: &MemRegion) -> bool {
        self.regions.values().any(|r| r.overlaps(region))
    }

    pub fn get_fragmentation_info(&self) -> (usize, u64) {
        let fragment_count = self.free_regions.len();
        let largest_free = self.free_regions.iter().map(|r| r.size as u64).max().unwrap_or(0);
        (fragment_count, largest_free)
    }

    pub fn protect_region(&mut self, region_id: u64, flags: RegionFlags) -> RegionResult<()> {
        let region = self.regions.get_mut(&region_id).ok_or(RegionError::NotFound)?;
        region.set_flag(flags);
        Ok(())
    }

    pub fn get_stats(&self, stats: &RegionStatistics) -> RegionStats {
        let (fragment_count, largest_free) = self.get_fragmentation_info();
        RegionStats {
            total_regions: self.regions.len(),
            free_regions: self.free_regions.len(),
            allocated_bytes: stats.allocated_bytes(),
            free_bytes: stats.free_bytes(),
            allocation_count: stats.allocation_count(),
            deallocation_count: stats.deallocation_count(),
            merge_count: stats.merge_count(),
            split_count: stats.split_count(),
            fragment_count,
            largest_free_block: largest_free,
        }
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub fn free_region_count(&self) -> usize {
        self.free_regions.len()
    }
}

impl Default for RegionManager {
    fn default() -> Self {
        Self::new()
    }
}
// ============================================================================
// GLOBAL STATE
// ============================================================================
use spin::Mutex;
static REGION_MANAGER: Mutex<RegionManager> = Mutex::new(RegionManager::new());
static REGION_STATS: RegionStatistics = RegionStatistics::new();
// ============================================================================
// PUBLIC API
// ============================================================================
pub fn init() -> super::error::RegionResult<()> {
    let mut manager = REGION_MANAGER.lock();
    manager.init(&REGION_STATS)
}

pub fn add_region(start: u64, size: usize, region_type: RegionType) -> super::error::RegionResult<u64> {
    let region = MemRegion::new(start, size, region_type);
    let mut manager = REGION_MANAGER.lock();
    manager.add_region(region, &REGION_STATS)
}

pub fn remove_region(region_id: u64) -> super::error::RegionResult<MemRegion> {
    let mut manager = REGION_MANAGER.lock();
    manager.remove_region(region_id, &REGION_STATS)
}

pub fn allocate_region(size: usize, region_type: RegionType) -> super::error::RegionResult<MemRegion> {
    let mut manager = REGION_MANAGER.lock();
    manager.allocate_region(size, region_type, layout::PAGE_SIZE as u64, &REGION_STATS)
}

pub fn allocate_aligned_region(
    size: usize,
    align: u64,
    region_type: RegionType,
) -> super::error::RegionResult<MemRegion> {
    let mut manager = REGION_MANAGER.lock();
    manager.allocate_region(size, region_type, align, &REGION_STATS)
}

pub fn deallocate_region(region: MemRegion) -> super::error::RegionResult<()> {
    let mut manager = REGION_MANAGER.lock();
    manager.deallocate_region(region, &REGION_STATS)
}

pub fn split_region(region_id: u64, offset: usize) -> super::error::RegionResult<(MemRegion, MemRegion)> {
    let mut manager = REGION_MANAGER.lock();
    manager.split_region(region_id, offset, &REGION_STATS)
}

pub fn protect_region(region_id: u64, flags: RegionFlags) -> super::error::RegionResult<()> {
    let mut manager = REGION_MANAGER.lock();
    manager.protect_region(region_id, flags)
}

pub fn merge_free_regions() {
    let mut manager = REGION_MANAGER.lock();
    manager.merge_adjacent_free_regions(&REGION_STATS);
}

pub fn find_region_by_address(addr: u64) -> Option<MemRegion> {
    let manager = REGION_MANAGER.lock();
    manager.find_region_by_address(addr).copied()
}

pub fn find_regions_by_type(region_type: RegionType) -> Vec<MemRegion> {
    let manager = REGION_MANAGER.lock();
    manager.find_regions_by_type(region_type)
}

pub fn is_region_available(start: u64, size: usize) -> bool {
    let manager = REGION_MANAGER.lock();
    let test_region = MemRegion::new(start, size, RegionType::Available);
    !manager.has_overlap(&test_region)
}

pub fn validate_region(region: &MemRegion) -> bool {
    region.is_valid()
}

pub fn get_region_stats() -> RegionStats {
    let manager = REGION_MANAGER.lock();
    manager.get_stats(&REGION_STATS)
}

pub fn get_largest_free_block() -> u64 {
    let stats = get_region_stats();
    stats.largest_free_block
}

pub fn get_fragmentation_ratio() -> f64 {
    let stats = get_region_stats();
    stats.fragmentation_ratio()
}

pub fn get_total_memory() -> u64 {
    let stats = get_region_stats();
    stats.total_memory()
}

pub fn get_available_memory() -> u64 {
    let stats = get_region_stats();
    stats.free_bytes
}

pub fn get_used_memory() -> u64 {
    let stats = get_region_stats();
    stats.allocated_bytes
}
