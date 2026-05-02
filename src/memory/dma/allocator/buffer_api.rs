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

use crate::memory::iommu::IommuDomain;

use super::super::coherency::DmaBuffer;
use super::super::error::DmaResult;
use super::super::types::{DmaConstraints, DmaDirection};
use super::api::{DMA_ALLOCATOR, DMA_STATS_GLOBAL};

pub fn alloc_buffer(
    size: usize,
    direction: DmaDirection,
    constraints: DmaConstraints,
) -> DmaResult<DmaBuffer> {
    DMA_ALLOCATOR.lock().allocate_buffer(size, direction, constraints, &DMA_STATS_GLOBAL)
}

pub fn alloc_buffer_iommu(
    size: usize,
    direction: DmaDirection,
    constraints: DmaConstraints,
    domain: &IommuDomain,
    iova: u64,
) -> DmaResult<DmaBuffer> {
    DMA_ALLOCATOR.lock().allocate_buffer_iommu(
        size,
        direction,
        constraints,
        domain,
        iova,
        &DMA_STATS_GLOBAL,
    )
}
