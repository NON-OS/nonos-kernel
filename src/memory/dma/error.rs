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

//! DMA Error Types
use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    NotInitialized,
    InvalidSize,
    FrameAllocationFailed,
    Dma32ConstraintFailed,
    AddressSpaceExhausted,
    MappingFailed,
    UnmappingFailed,
    RegionNotFound,
    MappingNotFound,
    TranslationFailed,
    PoolFull,
    DoubleFree,
    NotInPool,
    InvalidAlignment,
    BufferNotFound,
}

impl DmaError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "DMA allocator not initialized",
            Self::InvalidSize => "Invalid allocation size",
            Self::FrameAllocationFailed => "Failed to allocate physical frame",
            Self::Dma32ConstraintFailed => "DMA32 constraint not satisfied",
            Self::AddressSpaceExhausted => "DMA virtual address space exhausted",
            Self::MappingFailed => "Failed to map DMA page",
            Self::UnmappingFailed => "Failed to unmap DMA page",
            Self::RegionNotFound => "DMA region not found",
            Self::MappingNotFound => "Streaming mapping not found",
            Self::TranslationFailed => "Address translation failed",
            Self::PoolFull => "DMA pool at capacity",
            Self::DoubleFree => "Double free detected",
            Self::NotInPool => "Region not found in pool",
            Self::InvalidAlignment => "Invalid alignment",
            Self::BufferNotFound => "DMA buffer not found",
        }
    }

    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::AddressSpaceExhausted | Self::FrameAllocationFailed
        )
    }

    pub const fn is_bug(&self) -> bool {
        matches!(
            self,
            Self::DoubleFree | Self::NotInPool | Self::RegionNotFound | Self::MappingNotFound
        )
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::NotInitialized | Self::InvalidSize | Self::Dma32ConstraintFailed
        )
    }
}

impl fmt::Display for DmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type DmaResult<T> = Result<T, DmaError>;
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
