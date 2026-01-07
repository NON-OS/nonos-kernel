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

use super::constants::*;
use super::error::{XhciError, XhciResult};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

pub struct DmaRegion {
    va: VirtAddr,
    pa: PhysAddr,
    size: usize,
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

        let dma_region =
            alloc_dma_coherent(size, constraints).map_err(|_| XhciError::DmaAllocationFailed(size))?;

        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        if pa.as_u64() % DMA_MIN_ALIGNMENT as u64 != 0 {
            return Err(XhciError::DmaBufferMisaligned(pa.as_u64()));
        }

        if zero {
            // SAFETY: va points to valid allocated memory of size bytes
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

        let dma_region =
            alloc_dma_coherent(size, constraints).map_err(|_| XhciError::DmaAllocationFailed(size))?;

        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        if pa.as_u64() % actual_alignment as u64 != 0 {
            return Err(XhciError::DmaBufferMisaligned(pa.as_u64()));
        }

        if zero {
            // SAFETY: va points to valid allocated memory of size bytes
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

    pub fn validate_offset(&self, offset: usize, len: usize) -> XhciResult<()> {
        let end = offset
            .checked_add(len)
            .ok_or(XhciError::TransferLengthOverflow)?;

        if end > self.size {
            return Err(XhciError::BufferSizeMismatch {
                expected: len,
                actual: self.size.saturating_sub(offset),
            });
        }

        Ok(())
    }

    pub fn ptr_at<T>(&self, offset: usize) -> XhciResult<*mut T> {
        self.validate_offset(offset, core::mem::size_of::<T>())?;
        // SAFETY: offset validated to be within bounds
        Ok(unsafe { (self.va.as_ptr::<u8>() as *mut u8).add(offset) as *mut T })
    }

    pub fn phys_at(&self, offset: usize) -> XhciResult<u64> {
        if offset >= self.size {
            return Err(XhciError::BufferSizeMismatch {
                expected: 1,
                actual: 0,
            });
        }
        Ok(self.pa.as_u64() + offset as u64)
    }

    pub fn clear(&self) {
        // SAFETY: va points to valid allocated memory of size bytes
        unsafe {
            ptr::write_bytes(self.va.as_mut_ptr::<u8>(), 0, self.size);
        }
    }

    pub fn clear_range(&self, offset: usize, len: usize) -> XhciResult<()> {
        self.validate_offset(offset, len)?;
        // SAFETY: offset and len validated to be within bounds
        unsafe {
            let ptr = (self.va.as_ptr::<u8>() as *mut u8).add(offset);
            ptr::write_bytes(ptr, 0, len);
        }
        Ok(())
    }

    pub fn copy_from(&self, offset: usize, data: &[u8]) -> XhciResult<()> {
        self.validate_offset(offset, data.len())?;
        // SAFETY: offset and data.len() validated to be within bounds
        unsafe {
            let dst = (self.va.as_ptr::<u8>() as *mut u8).add(offset);
            ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    }

    pub fn copy_to(&self, offset: usize, data: &mut [u8]) -> XhciResult<()> {
        self.validate_offset(offset, data.len())?;
        // SAFETY: offset and data.len() validated to be within bounds
        unsafe {
            let src = self.va.as_ptr::<u8>().add(offset);
            ptr::copy_nonoverlapping(src, data.as_mut_ptr(), data.len());
        }
        Ok(())
    }

    pub fn read<T: Copy>(&self, offset: usize) -> XhciResult<T> {
        self.validate_offset(offset, core::mem::size_of::<T>())?;
        // SAFETY: offset validated to be within bounds
        unsafe {
            let ptr = self.va.as_ptr::<u8>().add(offset) as *const T;
            Ok(ptr::read_volatile(ptr))
        }
    }

    pub fn write<T: Copy>(&self, offset: usize, value: T) -> XhciResult<()> {
        self.validate_offset(offset, core::mem::size_of::<T>())?;
        // SAFETY: offset validated to be within bounds
        unsafe {
            let ptr = (self.va.as_ptr::<u8>() as *mut u8).add(offset) as *mut T;
            ptr::write_volatile(ptr, value);
        }
        Ok(())
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.va.as_ptr::<u8>(), self.size)
    }

    pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.va.as_mut_ptr::<u8>(), self.size)
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        self.clear();
    }
}

pub struct DmaRegionBuilder {
    size: usize,
    alignment: usize,
    zero: bool,
    for_trb: bool,
}

impl DmaRegionBuilder {
    pub fn new(size: usize) -> Self {
        Self {
            size,
            alignment: DMA_MIN_ALIGNMENT,
            zero: true,
            for_trb: false,
        }
    }

    pub fn alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment;
        self
    }

    pub fn for_trb(mut self) -> Self {
        self.for_trb = true;
        self.alignment = self.alignment.max(TRB_ALIGNMENT as usize);
        self
    }

    pub fn zero(mut self, zero: bool) -> Self {
        self.zero = zero;
        self
    }

    pub fn build(self) -> XhciResult<DmaRegion> {
        if self.for_trb && self.alignment < TRB_ALIGNMENT as usize {
            return Err(XhciError::TrbMisaligned(0));
        }
        DmaRegion::new_aligned(self.size, self.alignment, self.zero)
    }
}

pub fn alloc_trb_ring(num_entries: usize) -> XhciResult<DmaRegion> {
    use super::trb::Trb;
    let size = num_entries * core::mem::size_of::<Trb>();
    DmaRegionBuilder::new(size).for_trb().build()
}

pub fn alloc_device_context() -> XhciResult<DmaRegion> {
    use super::types::DeviceContext;
    DmaRegion::new_aligned(core::mem::size_of::<DeviceContext>(), 64, true)
}

pub fn alloc_input_context() -> XhciResult<DmaRegion> {
    use super::types::InputContext;
    DmaRegion::new_aligned(core::mem::size_of::<InputContext>(), 64, true)
}

pub fn alloc_dcbaa(max_slots: usize) -> XhciResult<DmaRegion> {
    let size = (max_slots + 1) * 8;
    DmaRegion::new_aligned(size, 64, true)
}

pub fn alloc_scratchpad_array(num_entries: usize) -> XhciResult<DmaRegion> {
    let size = num_entries * 8;
    DmaRegion::new_aligned(size, 64, true)
}

pub fn alloc_scratchpad_buffer() -> XhciResult<DmaRegion> {
    DmaRegion::new_aligned(4096, 4096, true)
}

pub fn alloc_erst(num_segments: usize) -> XhciResult<DmaRegion> {
    use super::types::ErstEntry;
    let size = num_segments * core::mem::size_of::<ErstEntry>();
    DmaRegion::new_aligned(size, 64, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_pattern() {
        let builder = DmaRegionBuilder::new(1024)
            .alignment(64)
            .for_trb()
            .zero(true);

        assert_eq!(builder.size, 1024);
        assert!(builder.alignment >= TRB_ALIGNMENT as usize);
    }
}
