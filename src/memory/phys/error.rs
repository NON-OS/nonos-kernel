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

//! Physical Memory Allocator Error Types

use core::fmt;

/// Errors from physical memory allocation operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysAllocError {
    /// Allocator not initialized
    NotInitialized,

    /// Invalid memory range (end <= start)
    InvalidRange,

    /// No complete pages in range after alignment
    NoCompletePagesInRange,

    /// Bitmap too small for memory range
    BitmapTooSmall,

    /// Invalid (null) bitmap pointer
    InvalidBitmapPointer,

    /// Frame address below managed range
    AddressBelowRange,

    /// Frame address above managed range
    AddressAboveRange,

    /// Frame address not page-aligned
    AddressNotAligned,

    /// Out of physical memory
    OutOfMemory,

    /// Double free detected
    DoubleFree,

    /// Frame not allocated
    FrameNotAllocated,

    /// Contiguous allocation range extends beyond managed memory
    RangeBeyondManaged,

    /// Zero frame count requested
    ZeroFrameCount,
}

impl PhysAllocError {
    /// Returns a human-readable description.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Physical memory allocator not initialized",
            Self::InvalidRange => "Physical memory range invalid: end <= start",
            Self::NoCompletePagesInRange => "No complete pages in range after alignment",
            Self::BitmapTooSmall => "Bitmap too small for managed memory range",
            Self::InvalidBitmapPointer => "Invalid bitmap pointer",
            Self::AddressBelowRange => "Frame address below managed range",
            Self::AddressAboveRange => "Frame address above managed range",
            Self::AddressNotAligned => "Frame address not page-aligned",
            Self::OutOfMemory => "Out of physical memory",
            Self::DoubleFree => "Double free detected",
            Self::FrameNotAllocated => "Frame not allocated",
            Self::RangeBeyondManaged => "Range extends beyond managed memory",
            Self::ZeroFrameCount => "Zero frame count requested",
        }
    }

    /// Returns true if this is a fatal error.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::OutOfMemory | Self::NotInitialized)
    }

    /// Returns true if this indicates memory corruption.
    pub fn indicates_corruption(&self) -> bool {
        matches!(
            self,
            Self::DoubleFree
                | Self::FrameNotAllocated
                | Self::AddressBelowRange
                | Self::AddressAboveRange
        )
    }
}

impl fmt::Display for PhysAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type for physical allocator operations.
pub type PhysAllocResult<T> = Result<T, PhysAllocError>;

impl From<&'static str> for PhysAllocError {
    fn from(s: &'static str) -> Self {
        match s {
            "Physical memory allocator not initialized" => Self::NotInitialized,
            "Physical memory range invalid: end <= start" => Self::InvalidRange,
            "No complete pages in range after alignment" => Self::NoCompletePagesInRange,
            "Bitmap too small for managed memory range" => Self::BitmapTooSmall,
            "Invalid bitmap pointer" => Self::InvalidBitmapPointer,
            "Frame address below managed range" => Self::AddressBelowRange,
            "Frame address above managed range" => Self::AddressAboveRange,
            "Frame address not page-aligned" => Self::AddressNotAligned,
            "Out of physical memory" => Self::OutOfMemory,
            "Double free detected or frame not allocated" => Self::DoubleFree,
            "Range extends beyond managed memory" => Self::RangeBeyondManaged,
            _ => Self::NotInitialized,
        }
    }
}
