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

use super::super::constants::{BC_TBL_ALIGNMENT, TB_ALIGNMENT, TFD_ALIGNMENT, TX_BUFFER_SIZE};
use super::super::error::WifiError;
use super::types::{validate_dma_phys_addr, TransferBuffer, TxFrameDescriptor};
use alloc::vec::Vec;
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints, DmaRegion};
use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::{PhysAddr, VirtAddr};

pub(crate) struct TxQueue {
    tfds_phys: PhysAddr,
    tfds_virt: VirtAddr,
    _bc_tbl_phys: PhysAddr,
    bc_tbl_virt: VirtAddr,
    buffers: Vec<Option<DmaRegion>>,
    write_ptr: AtomicU32,
    read_ptr: u32,
    size: usize,
    id: u8,
}

impl TxQueue {
    pub(crate) fn new(id: u8, size: usize) -> Result<Self, WifiError> {
        let tfd_size = size * core::mem::size_of::<TxFrameDescriptor>();
        let constraints = DmaConstraints {
            alignment: TFD_ALIGNMENT,
            max_segment_size: tfd_size,
            dma32_only: false,
            coherent: true,
        };

        let tfd_region =
            alloc_dma_coherent(tfd_size, constraints).map_err(|_| WifiError::DmaError)?;

        // SAFETY: tfd_region is valid DMA memory with sufficient size.
        unsafe {
            core::ptr::write_bytes(tfd_region.virt_addr.as_mut_ptr::<u8>(), 0, tfd_size);
        }

        let bc_size = size * 2;
        let bc_constraints = DmaConstraints {
            alignment: BC_TBL_ALIGNMENT,
            max_segment_size: bc_size,
            dma32_only: false,
            coherent: true,
        };

        let bc_region =
            alloc_dma_coherent(bc_size, bc_constraints).map_err(|_| WifiError::DmaError)?;

        // SAFETY: bc_region is valid DMA memory with sufficient size.
        unsafe {
            core::ptr::write_bytes(bc_region.virt_addr.as_mut_ptr::<u8>(), 0, bc_size);
        }

        let mut buffers = Vec::with_capacity(size);
        for _ in 0..size {
            buffers.push(None);
        }

        Ok(Self {
            tfds_phys: tfd_region.phys_addr,
            tfds_virt: tfd_region.virt_addr,
            _bc_tbl_phys: bc_region.phys_addr,
            bc_tbl_virt: bc_region.virt_addr,
            buffers,
            write_ptr: AtomicU32::new(0),
            read_ptr: 0,
            size,
            id,
        })
    }

    pub(crate) fn id(&self) -> u8 {
        self.id
    }

    pub(crate) fn phys_addr(&self) -> PhysAddr {
        self.tfds_phys
    }

    pub(crate) fn _bc_tbl_phys(&self) -> PhysAddr {
        self._bc_tbl_phys
    }

    pub(crate) fn write_ptr(&self) -> u32 {
        self.write_ptr.load(Ordering::Acquire)
    }

    pub(crate) fn available_space(&self) -> usize {
        let write = self.write_ptr.load(Ordering::Acquire) as usize;
        let read = self.read_ptr as usize;
        if write >= read {
            self.size - (write - read) - 1
        } else {
            read - write - 1
        }
    }

    pub(crate) fn enqueue(&mut self, data: &[u8]) -> Result<u32, WifiError> {
        if self.available_space() == 0 {
            return Err(WifiError::BufferTooSmall);
        }

        if data.len() > TX_BUFFER_SIZE {
            return Err(WifiError::BufferTooSmall);
        }

        if data.is_empty() {
            return Err(WifiError::InvalidParameter);
        }

        let idx = self.write_ptr.load(Ordering::Acquire) as usize;

        let constraints = DmaConstraints {
            alignment: TB_ALIGNMENT,
            max_segment_size: TX_BUFFER_SIZE,
            dma32_only: false,
            coherent: true,
        };

        let region =
            alloc_dma_coherent(TX_BUFFER_SIZE, constraints).map_err(|_| WifiError::DmaError)?;

        validate_dma_phys_addr(region.phys_addr)?;

        // SAFETY: region is valid DMA memory, data.len() <= TX_BUFFER_SIZE.
        unsafe {
            let buf_ptr = region.virt_addr.as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());
        }

        // SAFETY: idx is bounded by size, tfds_virt points to valid TFD array.
        let tfd_ptr = unsafe {
            &mut *(self
                .tfds_virt
                .as_mut_ptr::<TxFrameDescriptor>()
                .add(idx))
        };

        tfd_ptr.tb[0] = TransferBuffer::new(region.phys_addr, data.len() as u16);
        tfd_ptr.num_tbs = 1;

        let bc_ptr = self.bc_tbl_virt.as_mut_ptr::<u16>();
        // SAFETY: idx is bounded by size, bc_tbl_virt points to valid memory.
        unsafe {
            *bc_ptr.add(idx) = (data.len() as u16) | (1 << 12);
        }

        self.buffers[idx] = Some(region);

        let new_write = ((idx + 1) % self.size) as u32;
        self.write_ptr.store(new_write, Ordering::Release);

        Ok(idx as u32)
    }

    pub(crate) fn _reclaim(&mut self, count: usize) {
        for _ in 0..count {
            let idx = self.read_ptr as usize;
            self.buffers[idx] = None;
            self.read_ptr = ((self.read_ptr as usize + 1) % self.size) as u32;
        }
    }
}
