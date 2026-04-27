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
use core::fmt;

impl fmt::Display for PhysAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

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
