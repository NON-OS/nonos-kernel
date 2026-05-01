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
use super::super::constants::{align_up, is_dma32_compatible, pages_needed, MAX_DMA_SIZE};
use super::super::error::{DmaError, DmaResult};
use super::super::stats::DmaStats;
use super::super::types::{DmaConstraints, DmaRegion};
use super::core::DmaAllocator;
use crate::memory::{frame_alloc, layout};
use alloc::vec::Vec;
use crate::memory::addr::VirtAddr;

impl DmaAllocator {
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
            let frame = frame_alloc::allocate_frame().ok_or(DmaError::FrameAllocationFailed)?;
            if constraints.dma32_only && !is_dma32_compatible(frame.as_u64()) {
                for prev_frame in allocated_frames {
                    let _ = frame_alloc::deallocate_frame(prev_frame);
                }
                return Err(DmaError::Dma32ConstraintFailed);
            }
            allocated_frames.push(frame);
        }
        let phys_addr = allocated_frames[0];
        for (i, frame) in allocated_frames.iter().enumerate() {
            let page_vaddr = VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
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
        unsafe {
            core::ptr::write_bytes(virt_addr.as_mut_ptr::<u8>(), 0, aligned_size);
        }
        Ok(region)
    }

    pub fn free_coherent(&mut self, virt_addr: VirtAddr, stats: &DmaStats) -> DmaResult<()> {
        let region = self.coherent_regions.remove(&virt_addr).ok_or(DmaError::RegionNotFound)?;
        let page_count = pages_needed(region.size);
        for i in 0..page_count {
            let page_vaddr = VirtAddr::new(virt_addr.as_u64() + (i * layout::PAGE_SIZE) as u64);
            let phys_addr = self.translate_to_physical(page_vaddr)?;
            self.unmap_dma_page(page_vaddr)?;
            let _ = frame_alloc::deallocate_frame(phys_addr);
        }
        self.reclaim_virtual_range(virt_addr.as_u64(), region.size);
        stats.record_coherent_free(region.size);
        Ok(())
    }
}
