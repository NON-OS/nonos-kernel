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

use super::super::constants::*;
use super::super::error::{XhciError, XhciResult};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use core::ptr;
use crate::memory::addr::{PhysAddr, VirtAddr};

pub struct DmaRegion {
    pub(super) va: VirtAddr,
    pub(super) pa: PhysAddr,
    pub(super) size: usize,
}

impl DmaRegion {
    pub fn new(size: usize, zero: bool) -> XhciResult<Self> {
        if size == 0 {
            return Err(XhciError::DmaAllocationFailed(0));
        }
        if size > MAX_TRANSFER_SIZE {
            return Err(XhciError::TransferTooLarge(size));
        }
        let constraints = DmaConstraints {
            alignment: DMA_MIN_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };
        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| XhciError::DmaAllocationFailed(size))?;
        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);
        if pa.as_u64() % DMA_MIN_ALIGNMENT as u64 != 0 {
            return Err(XhciError::DmaBufferMisaligned(pa.as_u64()));
        }
        if zero {
            unsafe {
                ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
            }
        }
        Ok(Self { va, pa, size })
    }

    pub fn new_aligned(size: usize, alignment: usize, zero: bool) -> XhciResult<Self> {
        if size == 0 {
            return Err(XhciError::DmaAllocationFailed(0));
        }
        if size > MAX_TRANSFER_SIZE {
            return Err(XhciError::TransferTooLarge(size));
        }
        let actual_alignment = alignment.max(DMA_MIN_ALIGNMENT);
        let constraints = DmaConstraints {
            alignment: actual_alignment,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };
        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| XhciError::DmaAllocationFailed(size))?;
        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);
        if pa.as_u64() % actual_alignment as u64 != 0 {
            return Err(XhciError::DmaBufferMisaligned(pa.as_u64()));
        }
        if zero {
            unsafe {
                ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
            }
        }
        Ok(Self { va, pa, size })
    }

    #[inline]
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.va.as_mut_ptr::<T>()
    }
    #[inline]
    pub fn as_ptr<T>(&self) -> *const T {
        self.va.as_ptr::<T>()
    }
    #[inline]
    pub fn phys(&self) -> u64 {
        self.pa.as_u64()
    }
    #[inline]
    pub fn phys_addr(&self) -> PhysAddr {
        self.pa
    }
    #[inline]
    pub fn virt(&self) -> VirtAddr {
        self.va
    }
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        unsafe {
            ptr::write_bytes(self.va.as_mut_ptr::<u8>(), 0, self.size);
        }
    }
}
