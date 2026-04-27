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
use core::fmt;

impl fmt::Display for BuddyAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

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
