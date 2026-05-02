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

use super::super::coherency::{Coherency, DmaBuffer};
use super::super::error::DmaResult;
use super::super::stats::DmaStats;
use super::super::types::{DmaConstraints, DmaDirection};
use super::core::DmaAllocator;

impl DmaAllocator {
    pub fn allocate_buffer(
        &mut self,
        size: usize,
        direction: DmaDirection,
        constraints: DmaConstraints,
        stats: &DmaStats,
    ) -> DmaResult<DmaBuffer> {
        let region = self.allocate_coherent(size, constraints, stats)?;
        let coherency = Coherency::from_bool(region.coherent);
        // SAFETY: ek@nonos.systems — `allocate_coherent` just produced
        // this region: it mapped the pages with device attributes,
        // proved the size, and recorded the cpu/bus address pair. The
        // `from_parts` contract is satisfied by the allocator's own
        // bookkeeping.
        Ok(unsafe {
            DmaBuffer::from_parts(region.virt_addr, region.phys_addr, region.size, direction, coherency)
        })
    }
}
