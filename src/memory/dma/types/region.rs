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

use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::dma::coherency::{Coherency, DmaBuffer};
use crate::memory::dma::types::DmaDirection;

// LIMIT: `DmaRegion` is the legacy descriptor for coherent allocations.
// New code should request `DmaBuffer` from the allocator directly. This
// struct will be removed once existing drivers migrate; the
// `as_dma_buffer` accessor below is the bridge until then.
#[derive(Debug, Clone, Copy)]
pub struct DmaRegion {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
    pub coherent: bool,
    pub dma32_compatible: bool,
}

impl DmaRegion {
    pub const fn new(
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        coherent: bool,
        dma32_compatible: bool,
    ) -> Self {
        Self { virt_addr, phys_addr, size, coherent, dma32_compatible }
    }

    pub const fn dma_addr(&self) -> u64 {
        self.phys_addr.as_u64()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.virt_addr.as_ptr()
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.virt_addr.as_mut_ptr()
    }

    /// Bridge a `DmaRegion` into the substrate `DmaBuffer` form. Coherent
    /// regions are bidirectional by default; the resulting buffer
    /// reflects the region's coherency flag.
    pub fn as_dma_buffer(&self) -> DmaBuffer {
        // SAFETY: ek@nonos.systems — a `DmaRegion` only exists because
        // the DMA allocator built and registered it; the allocator owns
        // the page mapping, the size, and the address pair. The
        // `from_parts` invariants are exactly the allocator's
        // bookkeeping reread.
        unsafe {
            DmaBuffer::from_parts(
                self.virt_addr,
                self.phys_addr,
                self.size,
                DmaDirection::Bidirectional,
                Coherency::from_bool(self.coherent),
            )
        }
    }
}
