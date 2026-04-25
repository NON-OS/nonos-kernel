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
use super::super::types::{MemRegion, RegionFlags, RegionStats, RegionType};
use super::core::RegionManager;
use crate::memory::layout;
use alloc::vec::Vec;
use spin::Mutex;

static REGION_MANAGER: Mutex<RegionManager> = Mutex::new(RegionManager::new());
static REGION_STATS: RegionStatistics = RegionStatistics::new();

pub fn init() -> RegionResult<()> {
    REGION_MANAGER.lock().init(&REGION_STATS)
}
pub fn add_region(start: u64, size: usize, region_type: RegionType) -> RegionResult<u64> {
    REGION_MANAGER.lock().add_region(MemRegion::new(start, size, region_type), &REGION_STATS)
}
pub fn remove_region(region_id: u64) -> RegionResult<MemRegion> {
    REGION_MANAGER.lock().remove_region(region_id, &REGION_STATS)
}
pub fn allocate_region(size: usize, region_type: RegionType) -> RegionResult<MemRegion> {
    REGION_MANAGER.lock().allocate_region(
        size,
        region_type,
        layout::PAGE_SIZE as u64,
        &REGION_STATS,
    )
}
pub fn allocate_aligned_region(
    size: usize,
    align: u64,
    region_type: RegionType,
) -> RegionResult<MemRegion> {
    REGION_MANAGER.lock().allocate_region(size, region_type, align, &REGION_STATS)
}
pub fn deallocate_region(region: MemRegion) -> RegionResult<()> {
    REGION_MANAGER.lock().deallocate_region(region, &REGION_STATS)
}
pub fn split_region(region_id: u64, offset: usize) -> RegionResult<(MemRegion, MemRegion)> {
    REGION_MANAGER.lock().split_region(region_id, offset, &REGION_STATS)
}
pub fn protect_region(region_id: u64, flags: RegionFlags) -> RegionResult<()> {
    REGION_MANAGER.lock().protect_region(region_id, flags)
}
pub fn merge_free_regions() {
    REGION_MANAGER.lock().merge_adjacent_free_regions(&REGION_STATS);
}
pub fn find_region_by_address(addr: u64) -> Option<MemRegion> {
    REGION_MANAGER.lock().find_region_by_address(addr).copied()
}
pub fn find_regions_by_type(region_type: RegionType) -> Vec<MemRegion> {
    REGION_MANAGER.lock().find_regions_by_type(region_type)
}
pub fn is_region_available(start: u64, size: usize) -> bool {
    !REGION_MANAGER.lock().has_overlap(&MemRegion::new(start, size, RegionType::Available))
}
pub fn validate_region(region: &MemRegion) -> bool {
    region.is_valid()
}
pub fn get_region_stats() -> RegionStats {
    REGION_MANAGER.lock().get_stats(&REGION_STATS)
}
pub fn get_largest_free_block() -> u64 {
    get_region_stats().largest_free_block
}
pub fn get_fragmentation_ratio() -> f64 {
    get_region_stats().fragmentation_ratio()
}
pub fn get_total_memory() -> u64 {
    get_region_stats().total_memory()
}
pub fn get_available_memory() -> u64 {
    get_region_stats().free_bytes
}
pub fn get_used_memory() -> u64 {
    get_region_stats().allocated_bytes
}
