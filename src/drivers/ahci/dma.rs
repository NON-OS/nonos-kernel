// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

//! Per-port DMA memory management.

use x86_64::{VirtAddr, PhysAddr};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

use super::error::AhciError;
use super::types::{CommandHeader, CommandTable};
use super::constants::{COMMAND_SLOTS_PER_PORT, COMMAND_TABLE_SLOT_SIZE};

pub(crate) struct SendPtr<T>(pub(crate) *mut T);

// SAFETY: Pointer points to DMA-coherent memory synchronized via Mutex.
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

pub(crate) struct PortDma {
    pub(crate) cl_dma_pa: PhysAddr,
    pub(crate) cl_entries: SendPtr<CommandHeader>,
    pub(crate) fis_dma_pa: PhysAddr,
    pub(crate) ct_dma_va: VirtAddr,
    pub(crate) ct_dma_pa: PhysAddr,
    pub(crate) ct_slot_size: usize,
}

impl PortDma {
    pub(crate) fn new() -> Result<Self, AhciError> {
        let cl_constraints = DmaConstraints {
            alignment: 1024,
            max_segment_size: 1024,
            dma32_only: true,
            coherent: true,
        };
        let cl_dma_region = alloc_dma_coherent(1024, cl_constraints)
            .map_err(|_| AhciError::DmaAllocationFailed)?;
        let (cl_va, cl_pa) = (cl_dma_region.virt_addr, cl_dma_region.phys_addr);

        // SAFETY: cl_va points to valid DMA memory we just allocated.
        unsafe { core::ptr::write_bytes(cl_va.as_mut_ptr::<u8>(), 0, 1024); }

        let fis_constraints = DmaConstraints {
            alignment: 256,
            max_segment_size: 256,
            dma32_only: true,
            coherent: true,
        };
        let fis_dma_region = alloc_dma_coherent(256, fis_constraints)
            .map_err(|_| AhciError::DmaAllocationFailed)?;
        let (fis_va, fis_pa) = (fis_dma_region.virt_addr, fis_dma_region.phys_addr);

        // SAFETY: fis_va points to valid DMA memory we just allocated.
        unsafe { core::ptr::write_bytes(fis_va.as_mut_ptr::<u8>(), 0, 256); }

        let ct_size = COMMAND_TABLE_SLOT_SIZE * COMMAND_SLOTS_PER_PORT;
        let ct_constraints = DmaConstraints {
            alignment: 128,
            max_segment_size: ct_size,
            dma32_only: true,
            coherent: true,
        };
        let ct_dma_region = alloc_dma_coherent(ct_size, ct_constraints)
            .map_err(|_| AhciError::DmaAllocationFailed)?;
        let (ct_va, ct_pa) = (ct_dma_region.virt_addr, ct_dma_region.phys_addr);

        // SAFETY: ct_va points to valid DMA memory we just allocated.
        unsafe { core::ptr::write_bytes(ct_va.as_mut_ptr::<u8>(), 0, ct_size); }

        Ok(Self {
            cl_dma_pa: cl_pa,
            cl_entries: SendPtr(cl_va.as_mut_ptr::<CommandHeader>()),
            fis_dma_pa: fis_pa,
            ct_dma_va: ct_va,
            ct_dma_pa: ct_pa,
            ct_slot_size: COMMAND_TABLE_SLOT_SIZE,
        })
    }

    #[inline]
    pub(crate) fn ct_for_slot(&self, slot: u32) -> (*mut CommandTable, PhysAddr) {
        debug_assert!(slot < COMMAND_SLOTS_PER_PORT as u32, "slot index out of bounds");
        let off = self.ct_slot_size as u64 * slot as u64;
        // SAFETY: slot is bounds-checked, ct_dma_va points to contiguous allocation.
        let va = unsafe {
            self.ct_dma_va.as_mut_ptr::<u8>().add(off as usize) as *mut CommandTable
        };
        let pa = PhysAddr::new(self.ct_dma_pa.as_u64() + off);
        (va, pa)
    }
}
