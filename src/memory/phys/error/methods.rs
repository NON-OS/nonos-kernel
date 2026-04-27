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

use super::types::PhysAllocError;

impl PhysAllocError {
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

    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::OutOfMemory | Self::NotInitialized)
    }

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
