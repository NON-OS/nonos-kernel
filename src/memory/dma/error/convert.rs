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

use super::types::DmaError;

impl From<&'static str> for DmaError {
    fn from(s: &'static str) -> Self {
        match s {
            "DMA allocator not initialized" => Self::NotInitialized,
            "Invalid allocation size" => Self::InvalidSize,
            "Failed to allocate physical frame" => Self::FrameAllocationFailed,
            "DMA32 constraint not satisfied" => Self::Dma32ConstraintFailed,
            "DMA virtual address space exhausted" => Self::AddressSpaceExhausted,
            "Failed to map DMA page" => Self::MappingFailed,
            "Failed to unmap DMA page" => Self::UnmappingFailed,
            "DMA region not found" => Self::RegionNotFound,
            "Streaming mapping not found" => Self::MappingNotFound,
            "Address translation failed" => Self::TranslationFailed,
            "DMA pool at capacity" => Self::PoolFull,
            "Double free detected" => Self::DoubleFree,
            "Region not found in pool" => Self::NotInPool,
            "DMA buffer not found" => Self::BufferNotFound,
            _ => Self::NotInitialized,
        }
    }
}
