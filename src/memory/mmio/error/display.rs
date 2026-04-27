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
use core::fmt;

impl fmt::Display for MmioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&'static str> for MmioError {
    fn from(s: &'static str) -> Self {
        match s {
            "MMIO manager not initialized" => Self::NotInitialized,
            "Invalid size" => Self::InvalidSize,
            "Physical address not page aligned" => Self::NotPageAligned,
            "MMIO virtual address space exhausted" => Self::AddressSpaceExhausted,
            "MMIO region not found" => Self::RegionNotFound,
            "Access beyond region bounds" => Self::AccessOutOfBounds,
            "Invalid MMIO base address" => Self::InvalidBaseAddress,
            "Failed to map MMIO page" => Self::MappingFailed,
            "Failed to unmap MMIO page" => Self::UnmapFailed,
            _ => Self::NotInitialized,
        }
    }
}
