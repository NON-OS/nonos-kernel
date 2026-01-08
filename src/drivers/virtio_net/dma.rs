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

use core::ptr;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use super::constants::DMA_ALIGNMENT;

#[derive(Clone)]
pub struct DmaRegion {
    va: VirtAddr,
    pa: PhysAddr,
    size: usize,
}

impl DmaRegion {
    pub fn new(size: usize) -> Result<Self, &'static str> {
        if size == 0 {
            return Err("DMA: cannot allocate zero-sized region");
        }

        let constraints = DmaConstraints {
            alignment: DMA_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };

        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| "Failed to allocate DMA region")?;
        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        // SAFETY: va is valid DMA memory we just allocated
        unsafe {
            ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
        }

        Ok(Self { va, pa, size })
    }

    pub fn with_alignment(size: usize, alignment: usize) -> Result<Self, &'static str> {
        if size == 0 {
            return Err("DMA: cannot allocate zero-sized region");
        }

        if !alignment.is_power_of_two() {
            return Err("DMA: alignment must be power of two");
        }

        let constraints = DmaConstraints {
            alignment,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };

        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| "Failed to allocate DMA region with alignment")?;
        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        // SAFETY: va is valid DMA memory we just allocated
        unsafe {
            ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
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
    pub fn phys(&self) -> PhysAddr {
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

    pub fn zero(&self) {
        // SAFETY: va is valid DMA memory
        unsafe {
            ptr::write_bytes(self.va.as_mut_ptr::<u8>(), 0, self.size);
        }
    }

    pub fn fill(&self, byte: u8) {
        // SAFETY: va is valid DMA memory
        unsafe {
            ptr::write_bytes(self.va.as_mut_ptr::<u8>(), byte, self.size);
        }
    }

    pub unsafe fn read_at<T: Copy>(&self, offset: usize) -> Option<T> {
        if offset + core::mem::size_of::<T>() > self.size {
            return None;
        }
        let ptr = (self.va.as_u64() as usize + offset) as *const T;
        Some(ptr::read_volatile(ptr))
    }

    pub unsafe fn write_at<T: Copy>(&self, offset: usize, value: T) -> bool {
        if offset + core::mem::size_of::<T>() > self.size {
            return false;
        }
        let ptr = (self.va.as_u64() as usize + offset) as *mut T;
        ptr::write_volatile(ptr, value);
        true
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.va.as_ptr(), self.size)
    }

    pub unsafe fn as_mut_slice(&self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.va.as_mut_ptr(), self.size)
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        self.zero();
    }
}

pub fn alloc_descriptor_table(entry_count: usize, entry_size: usize) -> Result<DmaRegion, &'static str> {
    let size = entry_count
        .checked_mul(entry_size)
        .ok_or("DMA: size overflow")?;
    DmaRegion::new(size)
}

pub fn alloc_ring(ring_size: usize) -> Result<DmaRegion, &'static str> {
    DmaRegion::with_alignment(ring_size, DMA_ALIGNMENT)
}

pub fn alloc_packet_buffer(buffer_size: usize) -> Result<DmaRegion, &'static str> {
    DmaRegion::new(buffer_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dma_region_size() {
    }
}
