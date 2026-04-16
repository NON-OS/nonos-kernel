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

use super::types::BuddyAllocError;

impl BuddyAllocError {
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
            Self::Overflow => "Integer overflow in allocation size",
        }
    }

    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::OutOfVirtualMemory | Self::FrameAllocationFailed)
    }

    pub fn indicates_corruption(&self) -> bool {
        matches!(self, Self::InvalidAddress | Self::DoubleFree | Self::BlockOutOfRange)
    }
}
