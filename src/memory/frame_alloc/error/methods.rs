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

use super::types::FrameAllocError;

impl FrameAllocError {
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

    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::OutOfFrames | Self::AlreadyInitialized)
    }
}
