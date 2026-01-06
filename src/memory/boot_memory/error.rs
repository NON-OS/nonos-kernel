// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMemoryError {
    NotInitialized,
    AlreadyInitialized,
    InvalidHandoffMagic,
    UnsupportedVersion,
    InvalidHandoffPointer,
    NoRegionsDefined,
    NoAvailableMemory,
    InvalidRegionBounds,
    OutOfMemory,
    AllocationTooLarge,
    InvalidAlignment,
    RegionNotFound,
    MemoryMapParseError,
    OverlappingRegions,
    TooManyRegions,
}

impl BootMemoryError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Boot memory manager not initialized",
            Self::AlreadyInitialized => "Boot memory manager already initialized",
            Self::InvalidHandoffMagic => "Invalid boot handoff magic number",
            Self::UnsupportedVersion => "Unsupported boot handoff version",
            Self::InvalidHandoffPointer => "Invalid boot handoff pointer",
            Self::NoRegionsDefined => "No memory regions defined",
            Self::NoAvailableMemory => "No available memory regions found",
            Self::InvalidRegionBounds => "Invalid region bounds",
            Self::OutOfMemory => "Out of memory",
            Self::AllocationTooLarge => "Requested allocation too large",
            Self::InvalidAlignment => "Invalid alignment value",
            Self::RegionNotFound => "Memory region not found",
            Self::MemoryMapParseError => "Failed to parse memory map",
            Self::OverlappingRegions => "Overlapping memory regions detected",
            Self::TooManyRegions => "Maximum region count exceeded",
        }
    }

    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::NoRegionsDefined
                | Self::NoAvailableMemory
                | Self::OutOfMemory
                | Self::OverlappingRegions
        )
    }

    pub fn can_use_defaults(&self) -> bool {
        matches!(
            self,
            Self::InvalidHandoffMagic
                | Self::UnsupportedVersion
                | Self::InvalidHandoffPointer
                | Self::MemoryMapParseError
        )
    }
}

impl fmt::Display for BootMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
pub type BootMemoryResult<T> = Result<T, BootMemoryError>;
impl From<&'static str> for BootMemoryError {
    fn from(s: &'static str) -> Self {
        match s {
            "Boot memory not initialized" => Self::NotInitialized,
            "Boot memory already initialized" => Self::AlreadyInitialized,
            "No available memory found" => Self::NoAvailableMemory,
            "No memory regions defined" => Self::NoRegionsDefined,
            "Invalid region bounds" => Self::InvalidRegionBounds,
            "Out of memory" => Self::OutOfMemory,
            _ => Self::NotInitialized,
        }
    }
}
