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

//! Frame Allocator Error Types
//!
//! Specific error types for physical frame allocation operations.

use core::fmt;

/// Errors that can occur during frame allocation operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocError {
    /// No physical frames available for allocation
    OutOfFrames,

    /// Frame allocator has not been initialized
    NotInitialized,

    /// Frame allocator is already initialized
    AlreadyInitialized,

    /// Physical memory allocator dependency not ready
    PhysAllocatorNotReady,

    /// Invalid memory region specified (start >= end)
    InvalidRegion,

    /// Memory region boundaries are not page-aligned
    RegionNotAligned,

    /// Attempted to free a frame that was not allocated
    FrameNotAllocated,

    /// Maximum number of memory regions exceeded
    TooManyRegions,

    /// Frame address is out of valid physical memory range
    AddressOutOfRange,

    /// Double free detected
    DoubleFree,
}

impl FrameAllocError {
    /// Returns a human-readable description of the error
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OutOfFrames => "No physical frames available",
            Self::NotInitialized => "Frame allocator not initialized",
            Self::AlreadyInitialized => "Frame allocator already initialized",
            Self::PhysAllocatorNotReady => "Physical memory allocator not ready",
            Self::InvalidRegion => "Invalid memory region: start >= end",
            Self::RegionNotAligned => "Memory region boundaries not page-aligned",
            Self::FrameNotAllocated => "Frame was not allocated",
            Self::TooManyRegions => "Maximum memory regions exceeded",
            Self::AddressOutOfRange => "Frame address out of range",
            Self::DoubleFree => "Double free detected",
        }
    }

    /// Returns true if this error might be recoverable with retry
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::OutOfFrames | Self::AlreadyInitialized)
    }
}

impl fmt::Display for FrameAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type alias for frame allocation operations
pub type FrameResult<T> = Result<T, FrameAllocError>;

// Conversion from legacy string errors
impl From<&'static str> for FrameAllocError {
    fn from(s: &'static str) -> Self {
        match s {
            "Invalid region: start >= end" => Self::InvalidRegion,
            "Region boundaries must be page-aligned" => Self::RegionNotAligned,
            "Frame allocator already initialized" => Self::AlreadyInitialized,
            "Physical memory allocator not initialized" => Self::PhysAllocatorNotReady,
            "Frame allocator not initialized" => Self::NotInitialized,
            _ => Self::OutOfFrames,
        }
    }
}
