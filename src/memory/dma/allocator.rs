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
use core::sync::atomic::{compiler_fence, Ordering};
use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
use super::error::{DmaError, DmaResult};
use super::stats::DmaStats;
use super::types::{DmaConstraints, DmaDirection, DmaRegion, StreamingMapping};
use crate::memory::{frame_alloc, layout, virt};

pub struct DmaAllocator {
    coherent_regions: BTreeMap<VirtAddr, DmaRegion>,
    streaming_mappings: BTreeMap<u64, StreamingMapping>,
    next_vaddr: u64,
    next_mapping_id: u64,
    initialized: bool,
}

impl DmaAllocator {
    pub const fn new() -> Self {
        Self {
            coherent_regions: BTreeMap::new(),
            streaming_mappings: BTreeMap::new(),
            next_vaddr: DMA_VADDR_BASE,
            next_mapping_id: 1,
            initialized: false,
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
        self.initialized = true;

        Ok(())
    }
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ========================================================================
    // COHERENT ALLOCATION
    // ========================================================================
    pub fn allocate_coherent(
        &mut self,
        size: usize,
        constraints: DmaConstraints,
        stats: &DmaStats,
    ) -> DmaResult<DmaRegion> {
        if !self.initialized {
            return Err(DmaError::NotInitialized);
        }

        if size == 0 || size > MAX_DMA_SIZE {
            return Err(DmaError::InvalidSize);
        }

        let aligned_size = align_up(size, constraints.alignment);
        let page_count = pages_needed(aligned_size);
        let virt_addr = self.allocate_virtual_range(aligned_size)?;
        let mut allocated_frames = Vec::new();
        for _ in 0..page_count {
            let frame =
                frame_alloc::allocate_frame().ok_or(DmaError::FrameAllocationFailed)?;
            if constraints.dma32_only && !is_dma32_compatible(frame.as_u64()) {
                for prev_frame in allocated_frames {
                    frame_alloc::deallocate_frame(prev_frame);
                }
                return Err(DmaError::Dma32ConstraintFailed);
            }

            allocated_frames.push(frame);
        }

        let phys_addr = allocated_frames[0];
        for (i, frame) in allocated_frames.iter().enumerate() {
            let page_vaddr =
                VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
            self.map_dma_page(page_vaddr, *frame, constraints.coherent)?;
        }

        let region = DmaRegion::new(
            virt_addr,
            phys_addr,
            aligned_size,
            constraints.coherent,
            constraints.dma32_only,
        );

        self.coherent_regions.insert(virt_addr, region);
        stats.record_coherent_alloc(aligned_size);
        // Zero the region
        // SAFETY: We just allocated and mapped this region
        unsafe {
            core::ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, aligned_size);
        }

        Ok(region)
    }

    pub fn free_coherent(&mut self, virt_addr: VirtAddr, stats: &DmaStats) -> DmaResult<()> {
        let region = self
            .coherent_regions
            .remove(&virt_addr)
            .ok_or(DmaError::RegionNotFound)?;
        let page_count = pages_needed(region.size);
        for i in 0..page_count {
            let page_vaddr =
                VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let phys_addr =
                PhysAddr::new(region.phys_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
            self.unmap_dma_page(page_vaddr)?;
            frame_alloc::deallocate_frame(phys_addr);
        }

        stats.record_coherent_free(region.size);

        Ok(())
    }

    // ========================================================================
    // STREAMING MAPPINGS
    // ========================================================================
    pub fn map_streaming(
        &mut self,
        buffer_va: VirtAddr,
        size: usize,
        direction: DmaDirection,
        constraints: DmaConstraints,
        stats: &DmaStats,
    ) -> DmaResult<u64> {
        let mapping_id = self.next_mapping_id;
        self.next_mapping_id += 1;
        let needs_bounce = self.needs_bounce_buffer(buffer_va, size, &constraints)?;
        let (dma_addr, bounce_buffer) = if needs_bounce {
            let bounce_region = self.allocate_coherent(size, constraints, stats)?;
            if direction.writes_to_device() {
                self.copy_buffer(buffer_va, bounce_region.virt_addr, size)?;
            }

            stats.record_bounce_usage(true);
            (bounce_region.phys_addr, Some(bounce_region))
        } else {
            let dma_addr = self.translate_to_physical(buffer_va)?;
            (dma_addr, None)
        };

        let mapping = StreamingMapping::new(
            mapping_id,
            buffer_va,
            dma_addr,
            size,
            direction,
            bounce_buffer,
        );

        self.streaming_mappings.insert(mapping_id, mapping);
        stats.record_streaming_map();
        Ok(mapping_id)
    }

    pub fn unmap_streaming(&mut self, mapping_id: u64, stats: &DmaStats) -> DmaResult<()> {
        let mapping = self
            .streaming_mappings
            .remove(&mapping_id)
            .ok_or(DmaError::MappingNotFound)?;
        if let Some(bounce_region) = mapping.bounce_buffer {
            if mapping.direction.reads_from_device() {
                self.copy_buffer(bounce_region.virt_addr, mapping.buffer_va, mapping.size)?;
            }

            self.free_coherent(bounce_region.virt_addr, stats)?;
            stats.record_bounce_usage(false);
        }

        stats.record_streaming_unmap();

        Ok(())
    }

    pub fn sync_for_device(&self, mapping_id: u64) -> DmaResult<()> {
        let mapping = self
            .streaming_mappings
            .get(&mapping_id)
            .ok_or(DmaError::MappingNotFound)?;
        if let Some(bounce_region) = mapping.bounce_buffer {
            if mapping.direction.writes_to_device() {
                self.copy_buffer(mapping.buffer_va, bounce_region.virt_addr, mapping.size)?;
            }
        }

        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    pub fn sync_for_cpu(&self, mapping_id: u64) -> DmaResult<()> {
        compiler_fence(Ordering::SeqCst);
        let mapping = self
            .streaming_mappings
            .get(&mapping_id)
            .ok_or(DmaError::MappingNotFound)?;
        if let Some(bounce_region) = mapping.bounce_buffer {
            if mapping.direction.reads_from_device() {
                self.copy_buffer(bounce_region.virt_addr, mapping.buffer_va, mapping.size)?;
            }
        }

        Ok(())
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================
    fn allocate_virtual_range(&mut self, size: usize) -> DmaResult<VirtAddr> {
        let aligned_size = align_up(size, layout::PAGE_SIZE);
        let aligned_addr = align_up(self.next_vaddr as usize, layout::PAGE_SIZE) as u64;

        if aligned_addr + aligned_size as u64 > DMA_VADDR_END {
            return Err(DmaError::AddressSpaceExhausted);
        }

        let virt_addr = VirtAddr::new(aligned_addr);
        self.next_vaddr = aligned_addr + aligned_size as u64;

        Ok(virt_addr)
    }

    fn map_dma_page(
        &self,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        coherent: bool,
    ) -> DmaResult<()> {
        // SAFETY: Mapping DMA page with proper flags
        unsafe {
            virt::map_page_4k(virt_addr, phys_addr, true, false, !coherent)
                .map_err(|_| DmaError::MappingFailed)?;
        }

        if coherent {
            compiler_fence(Ordering::SeqCst);
        }

        Ok(())
    }

    fn unmap_dma_page(&self, virt_addr: VirtAddr) -> DmaResult<()> {
        // SAFETY: Unmapping previously mapped DMA page
        unsafe {
            virt::unmap_page(virt_addr).map_err(|_| DmaError::UnmappingFailed)?;
        }

        Ok(())
    }

    fn needs_bounce_buffer(
        &self,
        buffer_va: VirtAddr,
        size: usize,
        constraints: &DmaConstraints,
    ) -> DmaResult<bool> {
        let page_count = pages_needed(size);
        let mut current_va = buffer_va;

        for _ in 0..page_count {
            let phys_addr = self.translate_to_physical(current_va)?;
            if constraints.dma32_only && !is_dma32_compatible(phys_addr.as_u64()) {
                return Ok(true);
            }

            if phys_addr.as_u64() % constraints.alignment as u64 != 0 {
                return Ok(true);
            }

            current_va = VirtAddr::new(current_va.as_u64() + layout::PAGE_SIZE as u64);
        }

        Ok(false)
    }

    fn translate_to_physical(&self, virt_addr: VirtAddr) -> DmaResult<PhysAddr> {
        // SAFETY: Translating valid virtual address
        unsafe { virt::translate_addr(virt_addr).map_err(|_| DmaError::TranslationFailed) }
    }

    fn copy_buffer(&self, src_va: VirtAddr, dst_va: VirtAddr, size: usize) -> DmaResult<()> {
        // SAFETY: Copying between valid buffers
        unsafe {
            let src = core::slice::from_raw_parts(src_va.as_ptr::<u8>(), size);
            let dst = core::slice::from_raw_parts_mut(dst_va.as_mut_ptr::<u8>(), size);
            dst.copy_from_slice(src);
        }
        Ok(())
    }

    // ========================================================================
    // QUERY METHODS
    // ========================================================================
    pub fn get_mapping_info(&self, mapping_id: u64) -> Option<StreamingMapping> {
        self.streaming_mappings.get(&mapping_id).copied()
    }

    pub fn get_region_info(&self, virt_addr: VirtAddr) -> Option<DmaRegion> {
        self.coherent_regions.get(&virt_addr).copied()
    }

    pub fn is_dma_region(&self, virt_addr: VirtAddr) -> bool {
        self.coherent_regions.contains_key(&virt_addr)
            || self.streaming_mappings.values().any(|m| {
                m.bounce_buffer
                    .map(|b| b.virt_addr == virt_addr)
                    .unwrap_or(false)
            })
    }

    pub fn get_allocated_regions(&self) -> Vec<DmaRegion> {
        self.coherent_regions.values().copied().collect()
    }

    pub fn find_by_phys_addr(&self, phys_addr: PhysAddr) -> Option<VirtAddr> {
        for (virt, region) in self.coherent_regions.iter() {
            if region.phys_addr == phys_addr {
                return Some(*virt);
            }
        }
        None
    }
}

impl Default for DmaAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// Public API
use spin::Mutex;
use super::pool::DmaPool;
use super::types::DmaStatsSnapshot;
static DMA_ALLOCATOR: Mutex<DmaAllocator> = Mutex::new(DmaAllocator::new());
static DMA_STATS_GLOBAL: DmaStats = DmaStats::new();
pub fn init() -> DmaResult<()> { DMA_ALLOCATOR.lock().init() }
pub fn init_dma_allocator() -> DmaResult<()> { init() }
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
    let region = alloc_coherent(size, DmaConstraints::default())?;
    Ok(region.phys_addr)
}

pub fn free_dma_buffer(phys_addr: PhysAddr, _size: usize) -> DmaResult<()> {
    let allocator = DMA_ALLOCATOR.lock();
    let virt_addr = allocator.find_by_phys_addr(phys_addr).ok_or(DmaError::BufferNotFound)?;
    drop(allocator);
    free_coherent(virt_addr)
}

pub fn map_streaming(buffer_va: VirtAddr, size: usize, direction: DmaDirection, constraints: DmaConstraints) -> DmaResult<u64> {
    DMA_ALLOCATOR.lock().map_streaming(buffer_va, size, direction, constraints, &DMA_STATS_GLOBAL)
}

pub fn map_streaming_safe(buffer_va: VirtAddr, size: usize, direction: DmaDirection, constraints: DmaConstraints) -> DmaResult<u64> {
    map_streaming(buffer_va, size, direction, constraints)
}

pub fn unmap_streaming(mapping_id: u64) -> DmaResult<()> {
    DMA_ALLOCATOR.lock().unmap_streaming(mapping_id, &DMA_STATS_GLOBAL)
}

pub fn sync_for_device(mapping_id: u64) -> DmaResult<()> { DMA_ALLOCATOR.lock().sync_for_device(mapping_id) }
pub fn sync_for_cpu(mapping_id: u64) -> DmaResult<()> { DMA_ALLOCATOR.lock().sync_for_cpu(mapping_id) }
pub fn create_dma_pool(size: usize, count: usize, constraints: DmaConstraints) -> DmaResult<DmaPool> {
    let mut pool = DmaPool::new(size, count, constraints)?;
    for _ in 0..count {
        let region = alloc_coherent(size, constraints)?;
        pool.add_region(region)?;
    }
    Ok(pool)
}

pub fn get_mapping_info(mapping_id: u64) -> Option<StreamingMapping> { DMA_ALLOCATOR.lock().get_mapping_info(mapping_id) }
pub fn get_region_info(virt_addr: VirtAddr) -> Option<DmaRegion> { DMA_ALLOCATOR.lock().get_region_info(virt_addr) }
pub fn is_dma_region(virt_addr: VirtAddr) -> bool { DMA_ALLOCATOR.lock().is_dma_region(virt_addr) }
pub fn get_allocated_regions() -> alloc::vec::Vec<DmaRegion> { DMA_ALLOCATOR.lock().get_allocated_regions() }
pub fn validate_dma_address(dma_addr: PhysAddr, size: usize, dma32_only: bool) -> bool {
    if dma32_only && !is_range_dma32_compatible(dma_addr.as_u64(), size) { return false; }
    if dma_addr.as_u64() % crate::memory::layout::PAGE_SIZE as u64 != 0 { return false; }
    true
}

pub fn get_stats() -> DmaStatsSnapshot { DMA_STATS_GLOBAL.snapshot() }
