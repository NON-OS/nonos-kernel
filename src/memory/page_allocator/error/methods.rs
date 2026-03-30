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

use super::types::PageAllocError;

impl PageAllocError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Page allocator not initialized",
            Self::InvalidSize => "Invalid allocation size",
            Self::FrameAllocationFailed => "Failed to allocate physical frame",
            Self::MappingFailed => "Failed to map virtual page",
            Self::PageNotFound => "Page not found",
            Self::UnmapFailed => "Failed to unmap virtual page",
            Self::TranslationFailed => "Address translation failed",
            Self::TooManyPages => "Maximum pages exceeded",
            Self::OutOfVirtualSpace => "Out of virtual address space",
            Self::AlreadyInitialized => "Already initialized",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::FrameAllocationFailed | Self::OutOfVirtualSpace | Self::AlreadyInitialized
        )
    }
}
