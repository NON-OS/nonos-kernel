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

use super::direction::DmaDirection;
use super::region::DmaRegion;
use crate::memory::addr::{PhysAddr, VirtAddr};
use crate::memory::dma::coherency::{Coherency, DmaBuffer};

// LIMIT: `StreamingMapping` is the legacy descriptor for one-shot DMA
// mappings, including bounce-buffer routing. The substrate's `DmaBuffer`
// covers the same surface with explicit coherency intent and integrated
// sync windows. This struct stays as the bounce-buffer carrier until
// drivers stop relying on `mapping_id`-keyed sync calls.
#[derive(Debug, Clone, Copy)]
pub struct StreamingMapping {
    pub mapping_id: u64,
    pub buffer_va: VirtAddr,
    pub dma_addr: PhysAddr,
    pub size: usize,
    pub direction: DmaDirection,
    pub bounce_buffer: Option<DmaRegion>,
}

impl StreamingMapping {
    pub const fn new(
        mapping_id: u64,
        buffer_va: VirtAddr,
        dma_addr: PhysAddr,
        size: usize,
        direction: DmaDirection,
        bounce_buffer: Option<DmaRegion>,
    ) -> Self {
        Self { mapping_id, buffer_va, dma_addr, size, direction, bounce_buffer }
    }

    pub const fn uses_bounce_buffer(&self) -> bool {
        self.bounce_buffer.is_some()
    }

    pub const fn dma_address(&self) -> u64 {
        self.dma_addr.as_u64()
    }

    /// Bridge into the substrate `DmaBuffer` form. Streaming mappings
    /// declare their coherency through their lifetime, not their flags;
    /// this conversion treats the buffer as `NonCoherent` so that the
    /// substrate sync windows do real cache work on backends that need
    /// it. If the underlying mapping is in fact bus-coherent the sync
    /// degrades to a fence — never wrong, only redundant.
    pub fn as_dma_buffer(&self) -> DmaBuffer {
        // SAFETY: ek@nonos.systems — the streaming mapping was built by
        // the DMA allocator's map_streaming path: `buffer_va` is the
        // caller-supplied buffer the allocator translated, `dma_addr` is
        // the address the device will see (bounce or direct), and the
        // declared `size` matches both. Those are exactly the
        // `from_parts` invariants.
        unsafe {
            DmaBuffer::from_parts(
                self.buffer_va,
                self.dma_addr,
                self.size,
                self.direction,
                Coherency::NonCoherent,
            )
        }
    }
}
