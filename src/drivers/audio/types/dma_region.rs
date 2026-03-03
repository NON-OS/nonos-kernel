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

use core::fmt;
use core::ptr;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

use super::super::constants::DMA_ALIGNMENT;
use super::super::error::AudioError;

pub struct DmaRegion {
    pub va: VirtAddr,
    pub pa: PhysAddr,
    pub size: usize,
}

// SAFETY: DmaRegion contains VirtAddr/PhysAddr which are wrapped u64s, access synchronized via Mutex
unsafe impl Send for DmaRegion {}
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    pub fn new(size: usize) -> Result<Self, AudioError> {
        if size == 0 {
            return Err(AudioError::InvalidParameter);
        }

        let constraints = DmaConstraints {
            alignment: DMA_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };

        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| AudioError::DmaAllocationFailed)?;

        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        // SAFETY: va is valid pointer to `size` bytes of DMA memory we just allocated
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
    pub fn phys(&self) -> u64 {
        self.pa.as_u64()
    }

    #[inline]
    pub fn virt(&self) -> VirtAddr {
        self.va
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    #[inline]
    pub fn in_bounds(&self, offset: usize) -> bool {
        offset < self.size
    }

    #[inline]
    pub fn validate_range(&self, offset: usize, len: usize) -> bool {
        offset.checked_add(len).map_or(false, |end| end <= self.size)
    }

    pub unsafe fn zero(&self) { unsafe {
        // SAFETY: caller ensures no concurrent access
        ptr::write_bytes(self.va.as_mut_ptr::<u8>(), 0, self.size);
    }}
}

impl fmt::Debug for DmaRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmaRegion")
            .field("va", &format_args!("{:#X}", self.va.as_u64()))
            .field("pa", &format_args!("{:#X}", self.pa.as_u64()))
            .field("size", &self.size)
            .finish()
    }
}
