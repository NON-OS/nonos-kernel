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

use super::super::coherency::DmaBuffer;
use super::super::error::{DmaError, DmaResult};
use super::super::types::{DmaDirection, DmaRegion};
use super::pool_struct::DmaPool;

impl DmaPool {
    pub fn add_region(&mut self, region: DmaRegion) -> DmaResult<()> {
        if self.regions.len() >= self.regions.capacity() {
            return Err(DmaError::PoolFull);
        }

        let index = self.regions.len();
        self.regions.push(region);
        self.free_regions.push(index);
        Ok(())
    }

    pub fn allocate(&mut self) -> Option<DmaRegion> {
        if let Some(index) = self.free_regions.pop() {
            self.allocated_count += 1;
            Some(self.regions[index])
        } else {
            None
        }
    }

    /// Pop a region from the pool and hand it back as a `DmaBuffer` with
    /// the caller's chosen direction. Returns `None` when the pool is
    /// exhausted.
    pub fn allocate_buffer(&mut self, direction: DmaDirection) -> Option<DmaBuffer> {
        let region = self.allocate()?;
        let mut buf = region.as_dma_buffer();
        if direction != DmaDirection::Bidirectional {
            // SAFETY: ek@nonos.systems — the buffer was just produced
            // from a pool region whose underlying allocation is
            // bidirectional-coherent. Reconstructing with a narrower
            // direction is sound because the addresses, size, and
            // coherency are unchanged; only the device's intended data
            // flow over this lifetime is being declared.
            buf = unsafe {
                DmaBuffer::from_parts(
                    region.virt_addr,
                    region.phys_addr,
                    region.size,
                    direction,
                    buf.coherency(),
                )
            };
        }
        Some(buf)
    }

    pub fn deallocate(&mut self, region: DmaRegion) -> DmaResult<()> {
        for (index, stored_region) in self.regions.iter().enumerate() {
            if stored_region.virt_addr == region.virt_addr
                && stored_region.phys_addr == region.phys_addr
            {
                if !self.free_regions.contains(&index) {
                    self.free_regions.push(index);
                    self.allocated_count = self.allocated_count.saturating_sub(1);
                    return Ok(());
                } else {
                    return Err(DmaError::DoubleFree);
                }
            }
        }
        Err(DmaError::NotInPool)
    }
}
