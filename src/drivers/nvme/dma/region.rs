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

use core::ptr;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::dma::{alloc_dma_coherent, DmaConstraints, DmaRegion as MemDmaRegion};

use super::super::constants::{KERNEL_PHYS_END, KERNEL_PHYS_START, MAX_DMA_SIZE, PAGE_SIZE};
use super::super::error::NvmeError;

pub struct DmaRegion {
    virt_addr: VirtAddr,
    phys_addr: PhysAddr,
    size: usize,
    _backing: Option<MemDmaRegion>,
}

impl DmaRegion {
    pub fn allocate(size: usize) -> Result<Self, NvmeError> {
        if size == 0 {
            return Err(NvmeError::DmaBufferSizeZero);
        }
        if size > MAX_DMA_SIZE {
            return Err(NvmeError::DmaBufferTooLarge);
        }

        let aligned_size = Self::align_size(size);
        let constraints = DmaConstraints {
            alignment: PAGE_SIZE,
            max_segment_size: aligned_size,
            dma32_only: false,
            coherent: true,
        };

        let region =
            alloc_dma_coherent(aligned_size, constraints).map_err(|_| NvmeError::DmaAllocationFailed)?;

        // SAFETY: region.virt_addr is valid and aligned, size is within bounds
        unsafe {
            ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, aligned_size);
        }

        Ok(Self {
            virt_addr: region.virt_addr,
            phys_addr: region.phys_addr,
            size: aligned_size,
            _backing: Some(region),
        })
    }

    pub fn allocate_aligned(size: usize, alignment: usize) -> Result<Self, NvmeError> {
        if size == 0 {
            return Err(NvmeError::DmaBufferSizeZero);
        }
        if size > MAX_DMA_SIZE {
            return Err(NvmeError::DmaBufferTooLarge);
        }

        let aligned_size = Self::align_to(size, alignment);
        let constraints = DmaConstraints {
            alignment,
            max_segment_size: aligned_size,
            dma32_only: false,
            coherent: true,
        };

        let region =
            alloc_dma_coherent(aligned_size, constraints).map_err(|_| NvmeError::DmaAllocationFailed)?;

        // SAFETY: region.virt_addr is valid and aligned, size is within bounds
        unsafe {
            ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, aligned_size);
        }

        Ok(Self {
            virt_addr: region.virt_addr,
            phys_addr: region.phys_addr,
            size: aligned_size,
            _backing: Some(region),
        })
    }

    #[inline]
    pub const fn virt_addr(&self) -> VirtAddr {
        self.virt_addr
    }

    #[inline]
    pub const fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    #[inline]
    pub const fn phys_u64(&self) -> u64 {
        self.phys_addr.as_u64()
    }

    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn as_ptr<T>(&self) -> *const T {
        self.virt_addr.as_ptr::<T>()
    }

    #[inline]
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.virt_addr.as_mut_ptr::<T>()
    }

    pub fn as_slice<T>(&self) -> &[T] {
        let count = self.size / core::mem::size_of::<T>();
        // SAFETY: virt_addr is valid, properly aligned, and size is correct
        unsafe { core::slice::from_raw_parts(self.as_ptr(), count) }
    }

    pub fn as_mut_slice<T>(&mut self) -> &mut [T] {
        let count = self.size / core::mem::size_of::<T>();
        // SAFETY: virt_addr is valid, properly aligned, and size is correct
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr(), count) }
    }

    pub fn zero(&mut self) {
        // SAFETY: virt_addr is valid and size is within bounds
        unsafe {
            ptr::write_bytes(self.virt_addr.as_mut_ptr::<u8>(), 0, self.size);
        }
    }

    pub fn copy_from(&mut self, src: &[u8]) {
        let len = core::cmp::min(src.len(), self.size);
        // SAFETY: both pointers are valid and non-overlapping
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), self.virt_addr.as_mut_ptr::<u8>(), len);
        }
    }

    pub fn copy_to(&self, dst: &mut [u8]) {
        let len = core::cmp::min(dst.len(), self.size);
        // SAFETY: both pointers are valid and non-overlapping
        unsafe {
            ptr::copy_nonoverlapping(self.virt_addr.as_ptr::<u8>(), dst.as_mut_ptr(), len);
        }
    }

    #[inline]
    pub(super) const fn align_size(size: usize) -> usize {
        Self::align_to(size, PAGE_SIZE)
    }

    #[inline]
    pub(super) const fn align_to(size: usize, alignment: usize) -> usize {
        (size + alignment - 1) & !(alignment - 1)
    }
}

// SAFETY: DmaRegion contains physical/virtual addresses that are valid from any thread.
unsafe impl Send for DmaRegion {}
unsafe impl Sync for DmaRegion {}

pub fn validate_dma_buffer(phys_addr: PhysAddr, size: usize) -> Result<(), NvmeError> {
    let start = phys_addr.as_u64();

    if size == 0 {
        return Err(NvmeError::DmaBufferSizeZero);
    }

    if size > MAX_DMA_SIZE {
        return Err(NvmeError::DmaBufferTooLarge);
    }

    let end = start
        .checked_add(size as u64)
        .ok_or(NvmeError::DmaBufferAddressOverflow)?;

    if start >= KERNEL_PHYS_START && start < KERNEL_PHYS_END {
        return Err(NvmeError::DmaBufferOverlapsKernel);
    }

    if end > KERNEL_PHYS_START && end <= KERNEL_PHYS_END {
        return Err(NvmeError::DmaBufferOverlapsKernel);
    }

    if start < KERNEL_PHYS_END && end > KERNEL_PHYS_START {
        return Err(NvmeError::DmaBufferOverlapsKernel);
    }

    Ok(())
}
