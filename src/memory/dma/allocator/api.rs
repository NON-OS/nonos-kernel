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
use super::super::constants::is_range_dma32_compatible;
use super::super::error::{DmaError, DmaResult};
use super::super::pool::DmaPool;
use super::super::stats::DmaStats;
use super::super::types::{
    DmaConstraints, DmaDirection, DmaRegion, DmaStatsSnapshot, StreamingMapping,
};
use super::core::DmaAllocator;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

static DMA_ALLOCATOR: Mutex<DmaAllocator> = Mutex::new(DmaAllocator::new());
static DMA_STATS_GLOBAL: DmaStats = DmaStats::new();

pub fn init() -> DmaResult<()> {
    DMA_ALLOCATOR.lock().init()
}
pub fn init_dma_allocator() -> DmaResult<()> {
    init()
}
pub fn alloc_coherent(size: usize, constraints: DmaConstraints) -> DmaResult<DmaRegion> {
    DMA_ALLOCATOR.lock().allocate_coherent(size, constraints, &DMA_STATS_GLOBAL)
}
pub fn alloc_coherent_safe(size: usize, constraints: DmaConstraints) -> DmaResult<DmaRegion> {
    alloc_coherent(size, constraints)
}
pub fn alloc_coherent_dma32(size: usize) -> DmaResult<DmaRegion> {
    alloc_coherent(size, DmaConstraints::dma32())
}
pub fn alloc_dma_coherent(size: usize, constraints: DmaConstraints) -> DmaResult<DmaRegion> {
    alloc_coherent(size, constraints)
}
pub fn free_coherent(virt_addr: VirtAddr) -> DmaResult<()> {
    DMA_ALLOCATOR.lock().free_coherent(virt_addr, &DMA_STATS_GLOBAL)
}
pub fn allocate_dma_buffer(size: usize) -> DmaResult<PhysAddr> {
    Ok(alloc_coherent(size, DmaConstraints::default())?.phys_addr)
}
pub fn free_dma_buffer(phys_addr: PhysAddr, _size: usize) -> DmaResult<()> {
    let virt_addr =
        DMA_ALLOCATOR.lock().find_by_phys_addr(phys_addr).ok_or(DmaError::BufferNotFound)?;
    free_coherent(virt_addr)
}
pub fn map_streaming(
    buffer_va: VirtAddr,
    size: usize,
    direction: DmaDirection,
    constraints: DmaConstraints,
) -> DmaResult<u64> {
    DMA_ALLOCATOR.lock().map_streaming(buffer_va, size, direction, constraints, &DMA_STATS_GLOBAL)
}
pub fn map_streaming_safe(
    buffer_va: VirtAddr,
    size: usize,
    direction: DmaDirection,
    constraints: DmaConstraints,
) -> DmaResult<u64> {
    map_streaming(buffer_va, size, direction, constraints)
}
pub fn unmap_streaming(mapping_id: u64) -> DmaResult<()> {
    DMA_ALLOCATOR.lock().unmap_streaming(mapping_id, &DMA_STATS_GLOBAL)
}
pub fn sync_for_device(mapping_id: u64) -> DmaResult<()> {
    DMA_ALLOCATOR.lock().sync_for_device(mapping_id)
}
pub fn sync_for_cpu(mapping_id: u64) -> DmaResult<()> {
    DMA_ALLOCATOR.lock().sync_for_cpu(mapping_id)
}

pub fn create_dma_pool(
    size: usize,
    count: usize,
    constraints: DmaConstraints,
) -> DmaResult<DmaPool> {
    let mut pool = DmaPool::new(size, count, constraints)?;
    for _ in 0..count {
        pool.add_region(alloc_coherent(size, constraints)?)?;
    }
    Ok(pool)
}

pub fn get_mapping_info(mapping_id: u64) -> Option<StreamingMapping> {
    DMA_ALLOCATOR.lock().get_mapping_info(mapping_id)
}
pub fn get_region_info(virt_addr: VirtAddr) -> Option<DmaRegion> {
    DMA_ALLOCATOR.lock().get_region_info(virt_addr)
}
pub fn is_dma_region(virt_addr: VirtAddr) -> bool {
    DMA_ALLOCATOR.lock().is_dma_region(virt_addr)
}
pub fn get_allocated_regions() -> alloc::vec::Vec<DmaRegion> {
    DMA_ALLOCATOR.lock().get_allocated_regions()
}

pub fn validate_dma_address(dma_addr: PhysAddr, size: usize, dma32_only: bool) -> bool {
    if dma32_only && !is_range_dma32_compatible(dma_addr.as_u64(), size) {
        return false;
    }
    dma_addr.as_u64() % crate::memory::layout::PAGE_SIZE as u64 == 0
}

pub fn get_stats() -> DmaStatsSnapshot {
    DMA_STATS_GLOBAL.snapshot()
}
