// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! Per-port DMA memory management for AHCI.

use x86_64::{VirtAddr, PhysAddr};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use super::error::AhciError;
use super::types::{CommandHeader, CommandTable};
use super::constants::{COMMAND_SLOTS_PER_PORT, COMMAND_TABLE_SLOT_SIZE};

/// Wrapper for raw pointer that implements Send.
///
/// # Safety
///
/// This is safe because the underlying memory is DMA-coherent memory
/// that is never deallocated during the controller's lifetime and
/// all access is synchronized through the port_dma Mutex.
pub(crate) struct SendPtr<T>(pub *mut T);

// SAFETY: The pointer points to DMA-coherent memory that persists for
// the lifetime of the controller. All access is synchronized via Mutex.
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

/// Per-port DMA memory allocations.
///
/// Each AHCI port requires dedicated DMA-coherent memory regions for:
/// - Command List: 32 command headers (1KB, 1KB-aligned)
/// - FIS Receive Area: Received FIS structures (256 bytes, 256-byte aligned)
/// - Command Tables: 32 tables, one per slot (8KB total, 128-byte aligned)
///
/// All memory is allocated from DMA-coherent pools to ensure cache coherency
/// with the AHCI hardware DMA engine.
pub struct PortDma {
    /// Command list virtual address
    pub cl_dma_va: VirtAddr,
    /// Command list physical address (programmed into PORT_CLB/CLBU)
    pub cl_dma_pa: PhysAddr,
    /// Pointer to command header array (32 entries)
    pub cl_entries: SendPtr<CommandHeader>,

    /// FIS receive area virtual address
    pub fis_dma_va: VirtAddr,
    /// FIS receive area physical address (programmed into PORT_FB/FBU)
    pub fis_dma_pa: PhysAddr,

    /// Command tables virtual address (base of 32 tables)
    pub ct_dma_va: VirtAddr,
    /// Command tables physical address
    pub ct_dma_pa: PhysAddr,
    /// Size of each command table slot in bytes
    pub ct_slot_size: usize,
}

impl PortDma {
    /// Allocates DMA-coherent memory for a port's command structures.
    ///
    /// # Returns
    ///
    /// `Ok(PortDma)` on success, `Err(AhciError::DmaAllocationFailed)` on failure.
    ///
    /// # Memory Layout
    ///
    /// - Command List: 1024 bytes at 1024-byte alignment (32 × 32-byte headers)
    /// - FIS Receive: 256 bytes at 256-byte alignment
    /// - Command Tables: 8192 bytes at 128-byte alignment (32 × 256-byte tables)
    pub fn new() -> Result<Self, AhciError> {
        // Allocate command list (1KB aligned per AHCI spec)
        let cl_constraints = DmaConstraints {
            alignment: 1024,
            max_segment_size: 1024,
            dma32_only: true,
            coherent: true,
        };
        let cl_dma_region = alloc_dma_coherent(1024, cl_constraints)
            .map_err(|_| AhciError::DmaAllocationFailed)?;
        let (cl_va, cl_pa) = (cl_dma_region.virt_addr, cl_dma_region.phys_addr);

        // SAFETY: cl_va is a valid pointer to 1024 bytes of DMA memory
        // that we just allocated. Zeroing ensures clean initial state.
        unsafe { core::ptr::write_bytes(cl_va.as_mut_ptr::<u8>(), 0, 1024); }

        // Allocate FIS receive area (256-byte aligned per AHCI spec)
        let fis_constraints = DmaConstraints {
            alignment: 256,
            max_segment_size: 256,
            dma32_only: true,
            coherent: true,
        };
        let fis_dma_region = alloc_dma_coherent(256, fis_constraints)
            .map_err(|_| AhciError::DmaAllocationFailed)?;
        let (fis_va, fis_pa) = (fis_dma_region.virt_addr, fis_dma_region.phys_addr);

        // SAFETY: fis_va is a valid pointer to 256 bytes of DMA memory.
        unsafe { core::ptr::write_bytes(fis_va.as_mut_ptr::<u8>(), 0, 256); }

        // Allocate command tables (128-byte aligned per AHCI spec)
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

        // SAFETY: ct_va is a valid pointer to ct_size bytes of DMA memory.
        unsafe { core::ptr::write_bytes(ct_va.as_mut_ptr::<u8>(), 0, ct_size); }

        Ok(Self {
            cl_dma_va: cl_va,
            cl_dma_pa: cl_pa,
            cl_entries: SendPtr(cl_va.as_mut_ptr::<CommandHeader>()),
            fis_dma_va: fis_va,
            fis_dma_pa: fis_pa,
            ct_dma_va: ct_va,
            ct_dma_pa: ct_pa,
            ct_slot_size: COMMAND_TABLE_SLOT_SIZE,
        })
    }
  
    /// Debug builds will panic if slot >= 32.
    #[inline]
    pub fn ct_for_slot(&self, slot: u32) -> (*mut CommandTable, PhysAddr) {
        debug_assert!(slot < COMMAND_SLOTS_PER_PORT as u32, "slot index out of bounds");
        let off = self.ct_slot_size as u64 * slot as u64;
        // SAFETY: slot is bounds-checked in debug mode, and ct_dma_va points
        // to a contiguous allocation of 32 command tables. The offset calculation
        // is within bounds for slot < 32.
        let va = unsafe {
            self.ct_dma_va.as_mut_ptr::<u8>().add(off as usize) as *mut CommandTable
        };
        let pa = PhysAddr::new(self.ct_dma_pa.as_u64() + off);
        (va, pa)
    }
}
