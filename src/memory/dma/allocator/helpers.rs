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

use super::super::constants::{align_up, is_dma32_compatible, pages_needed, DMA_VADDR_END};
use super::super::error::{DmaError, DmaResult};
use super::super::types::DmaConstraints;
use super::core::DmaAllocator;
use crate::memory::{layout, virt};
use core::sync::atomic::{compiler_fence, Ordering};
use crate::memory::addr::{PhysAddr, VirtAddr};

impl DmaAllocator {
    pub(super) fn allocate_virtual_range(&mut self, size: usize) -> DmaResult<VirtAddr> {
        let aligned_size = align_up(size, layout::PAGE_SIZE);
        if let Some(addr) = self.try_reuse_virtual_range(aligned_size) {
            return Ok(VirtAddr::new(addr));
        }
        let aligned_addr = align_up(self.next_vaddr as usize, layout::PAGE_SIZE) as u64;
        if aligned_addr + aligned_size as u64 > DMA_VADDR_END {
            return Err(DmaError::AddressSpaceExhausted);
        }
        self.next_vaddr = aligned_addr + aligned_size as u64;
        Ok(VirtAddr::new(aligned_addr))
    }

    pub(super) fn map_dma_page(
        &self,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        coherent: bool,
    ) -> DmaResult<()> {
        virt::map_page_4k(virt_addr, phys_addr, true, false, !coherent)
            .map_err(|_| DmaError::MappingFailed)?;
        if coherent {
            compiler_fence(Ordering::SeqCst);
        }
        Ok(())
    }

    pub(super) fn unmap_dma_page(&self, virt_addr: VirtAddr) -> DmaResult<()> {
        virt::unmap_page(virt_addr).map_err(|_| DmaError::UnmappingFailed)
    }

    pub(super) fn needs_bounce_buffer(
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

    pub(super) fn translate_to_physical(&self, virt_addr: VirtAddr) -> DmaResult<PhysAddr> {
        virt::translate_addr(virt_addr).map_err(|_| DmaError::TranslationFailed)
    }

    pub(super) fn copy_buffer(
        &self,
        src_va: VirtAddr,
        dst_va: VirtAddr,
        size: usize,
    ) -> DmaResult<()> {
        unsafe {
            let src = core::slice::from_raw_parts(src_va.as_ptr::<u8>(), size);
            let dst = core::slice::from_raw_parts_mut(dst_va.as_mut_ptr::<u8>(), size);
            dst.copy_from_slice(src);
        }
        Ok(())
    }
}
