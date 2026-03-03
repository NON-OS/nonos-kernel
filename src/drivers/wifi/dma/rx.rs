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

use super::super::constants::{
    RX_BD_ALIGNMENT, RX_BUFFER_ALIGNMENT, RX_BUFFER_SIZE, RX_STATUS_ALIGNMENT, RX_STATUS_PTR_MASK,
};
use super::super::error::WifiError;
use super::types::validate_dma_phys_addr;
use alloc::vec::Vec;
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints, DmaRegion};
use x86_64::{PhysAddr, VirtAddr};

pub(crate) struct RxQueue {
    rb_stts_phys: PhysAddr,
    rb_stts_virt: VirtAddr,
    bd_phys: PhysAddr,
    bd_virt: VirtAddr,
    buffers: Vec<DmaRegion>,
    write_ptr: u32,
    size: usize,
}

impl RxQueue {
    pub(crate) fn new(size: usize) -> Result<Self, WifiError> {
        let bd_size = size * 8;
        let constraints = DmaConstraints {
            alignment: RX_BD_ALIGNMENT,
            max_segment_size: bd_size,
            dma32_only: false,
            coherent: true,
        };

        let bd_region =
            alloc_dma_coherent(bd_size, constraints).map_err(|_| WifiError::DmaError)?;

        let stts_constraints = DmaConstraints {
            alignment: RX_STATUS_ALIGNMENT,
            max_segment_size: RX_STATUS_ALIGNMENT,
            dma32_only: false,
            coherent: true,
        };

        let stts_region =
            alloc_dma_coherent(16, stts_constraints).map_err(|_| WifiError::DmaError)?;

        let mut buffers = Vec::with_capacity(size);
        let bd_ptr = bd_region.virt_addr.as_mut_ptr::<u64>();

        for i in 0..size {
            let buf_constraints = DmaConstraints {
                alignment: RX_BUFFER_ALIGNMENT,
                max_segment_size: RX_BUFFER_SIZE,
                dma32_only: false,
                coherent: true,
            };

            let buf = alloc_dma_coherent(RX_BUFFER_SIZE, buf_constraints)
                .map_err(|_| WifiError::DmaError)?;

            // SAFETY: i is bounded by size, bd_ptr points to valid BD array.
            unsafe {
                *bd_ptr.add(i) = buf.phys_addr.as_u64();
            }

            buffers.push(buf);
        }

        Ok(Self {
            rb_stts_phys: stts_region.phys_addr,
            rb_stts_virt: stts_region.virt_addr,
            bd_phys: bd_region.phys_addr,
            bd_virt: bd_region.virt_addr,
            buffers,
            write_ptr: 0,
            size,
        })
    }

    pub(crate) fn bd_phys(&self) -> PhysAddr {
        self.bd_phys
    }

    pub(crate) fn stts_phys(&self) -> PhysAddr {
        self.rb_stts_phys
    }

    pub(crate) fn write_ptr(&self) -> u32 {
        self.write_ptr
    }

    pub(crate) fn set_write_ptr(&mut self, val: u32) {
        self.write_ptr = val;
    }

    pub(crate) fn hw_read_ptr(&self) -> u32 {
        // SAFETY: rb_stts_virt points to valid DMA status memory.
        unsafe {
            let stts = self.rb_stts_virt.as_ptr::<u32>();
            (*stts) & RX_STATUS_PTR_MASK
        }
    }

    pub(crate) fn get_buffer(&self, idx: usize) -> &[u8] {
        let buf = &self.buffers[idx % self.size];
        // SAFETY: buffer was allocated with RX_BUFFER_SIZE, idx bounded by modulo.
        unsafe { core::slice::from_raw_parts(buf.virt_addr.as_ptr(), RX_BUFFER_SIZE) }
    }

    pub(crate) fn replenish(&mut self, idx: usize) -> Result<(), WifiError> {
        let buf_constraints = DmaConstraints {
            alignment: RX_BUFFER_ALIGNMENT,
            max_segment_size: RX_BUFFER_SIZE,
            dma32_only: false,
            coherent: true,
        };

        let new_buf =
            alloc_dma_coherent(RX_BUFFER_SIZE, buf_constraints).map_err(|_| WifiError::DmaError)?;

        validate_dma_phys_addr(new_buf.phys_addr)?;

        let bd_ptr = self.bd_virt.as_mut_ptr::<u64>();
        // SAFETY: idx bounded by modulo size, bd_ptr points to valid BD array.
        unsafe {
            *bd_ptr.add(idx % self.size) = new_buf.phys_addr.as_u64();
        }

        self.buffers[idx % self.size] = new_buf;
        Ok(())
    }
}
