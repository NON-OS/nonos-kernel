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

use super::constants::{
    BC_TBL_ALIGNMENT, KERNEL_PHYS_MASK, KERNEL_RESERVED_SIZE, RX_BD_ALIGNMENT,
    RX_BUFFER_ALIGNMENT, RX_BUFFER_SIZE, RX_STATUS_ALIGNMENT, RX_STATUS_PTR_MASK,
    TB_ALIGNMENT, TFD_ALIGNMENT, TX_BUFFER_SIZE,
};
use super::error::WifiError;
use alloc::vec::Vec;
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints, DmaRegion};
use crate::memory::layout::KERNEL_BASE;
use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::{PhysAddr, VirtAddr};

const MAX_DMA_PHYS_ADDR: u64 = 0x1_0000_0000_0000;

fn validate_dma_phys_addr(addr: PhysAddr) -> Result<(), WifiError> {
    let raw = addr.as_u64();
    if raw == 0 {
        return Err(WifiError::InvalidParameter);
    }
    if raw >= MAX_DMA_PHYS_ADDR {
        return Err(WifiError::DmaError);
    }
    let kernel_phys_base = KERNEL_BASE as u64 & KERNEL_PHYS_MASK;
    if raw >= kernel_phys_base && raw < kernel_phys_base + KERNEL_RESERVED_SIZE {
        return Err(WifiError::DmaError);
    }
    Ok(())
}

#[repr(C, align(256))]
pub struct TxFrameDescriptor {
    pub tb: [TransferBuffer; 20],
    pub num_tbs: u32,
    _pad: [u8; 12],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TransferBuffer {
    pub lo: u32,
    pub hi_n_len: u32,
}

impl TransferBuffer {
    pub fn new(addr: PhysAddr, len: u16) -> Self {
        Self {
            lo: addr.as_u64() as u32,
            hi_n_len: ((addr.as_u64() >> 32) as u32 & 0xFF) | ((len as u32) << 16),
        }
    }
}

impl Default for TxFrameDescriptor {
    fn default() -> Self {
        Self {
            tb: [TransferBuffer::default(); 20],
            num_tbs: 0,
            _pad: [0; 12],
        }
    }
}

pub struct TxQueue {
    tfds_phys: PhysAddr,
    tfds_virt: VirtAddr,
    bc_tbl_phys: PhysAddr,
    bc_tbl_virt: VirtAddr,
    buffers: Vec<Option<DmaRegion>>,
    write_ptr: AtomicU32,
    read_ptr: u32,
    size: usize,
    id: u8,
}

impl TxQueue {
    pub fn new(id: u8, size: usize) -> Result<Self, WifiError> {
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
            bc_tbl_phys: bc_region.phys_addr,
            bc_tbl_virt: bc_region.virt_addr,
            buffers,
            write_ptr: AtomicU32::new(0),
            read_ptr: 0,
            size,
            id,
        })
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn phys_addr(&self) -> PhysAddr {
        self.tfds_phys
    }

    pub fn bc_tbl_phys(&self) -> PhysAddr {
        self.bc_tbl_phys
    }

    pub fn write_ptr(&self) -> u32 {
        self.write_ptr.load(Ordering::Acquire)
    }

    pub fn available_space(&self) -> usize {
        let write = self.write_ptr.load(Ordering::Acquire) as usize;
        let read = self.read_ptr as usize;
        if write >= read {
            self.size - (write - read) - 1
        } else {
            read - write - 1
        }
    }

    pub fn enqueue(&mut self, data: &[u8]) -> Result<u32, WifiError> {
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

    pub fn reclaim(&mut self, count: usize) {
        for _ in 0..count {
            let idx = self.read_ptr as usize;
            self.buffers[idx] = None;
            self.read_ptr = ((self.read_ptr as usize + 1) % self.size) as u32;
        }
    }
}

pub struct RxQueue {
    rb_stts_phys: PhysAddr,
    rb_stts_virt: VirtAddr,
    bd_phys: PhysAddr,
    bd_virt: VirtAddr,
    buffers: Vec<DmaRegion>,
    write_ptr: u32,
    size: usize,
}

impl RxQueue {
    pub fn new(size: usize) -> Result<Self, WifiError> {
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

    pub fn bd_phys(&self) -> PhysAddr {
        self.bd_phys
    }

    pub fn stts_phys(&self) -> PhysAddr {
        self.rb_stts_phys
    }

    pub fn write_ptr(&self) -> u32 {
        self.write_ptr
    }

    pub fn set_write_ptr(&mut self, val: u32) {
        self.write_ptr = val;
    }

    pub fn hw_read_ptr(&self) -> u32 {
        // SAFETY: rb_stts_virt points to valid DMA status memory.
        unsafe {
            let stts = self.rb_stts_virt.as_ptr::<u32>();
            (*stts) & RX_STATUS_PTR_MASK
        }
    }

    pub fn get_buffer(&self, idx: usize) -> &[u8] {
        let buf = &self.buffers[idx % self.size];
        // SAFETY: buffer was allocated with RX_BUFFER_SIZE, idx bounded by modulo.
        unsafe { core::slice::from_raw_parts(buf.virt_addr.as_ptr(), RX_BUFFER_SIZE) }
    }

    pub fn replenish(&mut self, idx: usize) -> Result<(), WifiError> {
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
