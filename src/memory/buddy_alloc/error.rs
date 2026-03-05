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

//! Buddy Allocator Error Types
//!
//! Error types for buddy allocator operations.

use core::fmt;

/// Errors that can occur during buddy allocator operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuddyAllocError {
    /// Allocator not initialized
    NotInitialized,

    /// Invalid allocation size (zero or too large)
    InvalidSize,

    /// Invalid page count
    InvalidPageCount,

    /// Invalid alignment (not power of two)
    InvalidAlignment,

    /// Allocation too large for buddy allocator
    AllocationTooLarge,

    /// Out of virtual memory
    OutOfVirtualMemory,

    /// Failed to allocate physical frame
    FrameAllocationFailed,

    /// Failed to map page
    MappingFailed,

    /// Invalid deallocation address
    InvalidAddress,

    /// Address translation failed
    TranslationFailed,

    /// Failed to unmap page
    UnmapFailed,

    /// Block outside valid range
    BlockOutOfRange,

    /// Double free detected
    DoubleFree,
}

impl BuddyAllocError {
    /// Returns a human-readable description of the error
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Allocator not initialized",
            Self::InvalidSize => "Invalid allocation size",
            Self::InvalidPageCount => "Invalid page count",
            Self::InvalidAlignment => "Invalid alignment (must be power of two)",
            Self::AllocationTooLarge => "Allocation too large",
            Self::OutOfVirtualMemory => "Out of virtual memory",
            Self::FrameAllocationFailed => "Failed to allocate physical frame",
            Self::MappingFailed => "Failed to map page",
            Self::InvalidAddress => "Invalid deallocation address",
            Self::TranslationFailed => "Address translation failed",
            Self::UnmapFailed => "Failed to unmap page",
            Self::BlockOutOfRange => "Block outside valid range",
            Self::DoubleFree => "Double free detected",
        }
    }

    /// Returns true if this is a fatal error
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::OutOfVirtualMemory | Self::FrameAllocationFailed
        )
    }

    /// Returns true if this indicates corruption
    pub fn indicates_corruption(&self) -> bool {
        matches!(
            self,
            Self::InvalidAddress | Self::DoubleFree | Self::BlockOutOfRange
        )
    }
}

impl fmt::Display for BuddyAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type alias for buddy allocator operations
pub type BuddyAllocResult<T> = Result<T, BuddyAllocError>;

impl From<&'static str> for BuddyAllocError {
    fn from(s: &'static str) -> Self {
        match s {
            "Allocator not initialized" => Self::NotInitialized,
            "Invalid allocation size" => Self::InvalidSize,
            "Invalid page count" => Self::InvalidPageCount,
            "Alignment must be power of two" => Self::InvalidAlignment,
            "Invalid allocation parameters" => Self::InvalidAlignment,
            "Allocation too large" => Self::AllocationTooLarge,
            "Out of virtual memory" => Self::OutOfVirtualMemory,
            "Failed to allocate physical frame" => Self::FrameAllocationFailed,
            "Failed to map page" => Self::MappingFailed,
            "Invalid deallocation address" => Self::InvalidAddress,
            "Address translation failed" => Self::TranslationFailed,
            "Failed to unmap page" => Self::UnmapFailed,
            "Block outside valid range" => Self::BlockOutOfRange,
            _ => Self::NotInitialized,
        }
    }
}
