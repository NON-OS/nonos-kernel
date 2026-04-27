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
use x86_64::{PhysAddr, VirtAddr};

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
}
