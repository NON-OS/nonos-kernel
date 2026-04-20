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

use super::types::MmioError;

impl MmioError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "MMIO manager not initialized",
            Self::InvalidSize => "Invalid size",
            Self::NotPageAligned => "Physical address not page aligned",
            Self::AddressSpaceExhausted => "MMIO virtual address space exhausted",
            Self::RegionNotFound => "MMIO region not found",
            Self::AccessOutOfBounds => "Access beyond region bounds",
            Self::InvalidBaseAddress => "Invalid MMIO base address",
            Self::MappingFailed => "Failed to map MMIO page",
            Self::UnmapFailed => "Failed to unmap MMIO page",
            Self::Overflow => "Integer overflow in MMIO operation",
        }
    }

    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::AddressSpaceExhausted | Self::MappingFailed | Self::UnmapFailed)
    }
}
