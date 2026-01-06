// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    NotInitialized,
    AlreadyInitialized,
    OutOfMemory,
    AllocationTooLarge,
    InvalidLayout,
    FrameAllocationFailed,
    MappingFailed,
    DoubleFree,
    HeapCorruption,
    BufferOverflow,
    InvalidPointer,
    PointerOutOfRange,
    SizeMismatch,
    IntegrityCheckFailed,
}

impl HeapError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Heap not initialized",
            Self::AlreadyInitialized => "Heap already initialized",
            Self::OutOfMemory => "Out of memory",
            Self::AllocationTooLarge => "Allocation size too large",
            Self::InvalidLayout => "Invalid allocation layout",
            Self::FrameAllocationFailed => "Failed to allocate physical frames",
            Self::MappingFailed => "Failed to map heap memory",
            Self::DoubleFree => "Double free detected",
            Self::HeapCorruption => "Heap corruption detected",
            Self::BufferOverflow => "Buffer overflow detected",
            Self::InvalidPointer => "Invalid pointer",
            Self::PointerOutOfRange => "Pointer outside heap range",
            Self::SizeMismatch => "Size mismatch during deallocation",
            Self::IntegrityCheckFailed => "Heap integrity check failed",
        }
    }

    pub fn is_security_critical(&self) -> bool {
        matches!(self, Self::DoubleFree | Self::HeapCorruption | Self::BufferOverflow | Self::InvalidPointer | Self::PointerOutOfRange)
    }

    pub fn indicates_corruption(&self) -> bool {
        matches!(self, Self::HeapCorruption | Self::BufferOverflow | Self::SizeMismatch | Self::IntegrityCheckFailed)
    }
}

impl fmt::Display for HeapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.as_str()) }
}

pub type HeapResult<T> = Result<T, HeapError>;
impl From<&'static str> for HeapError {
    fn from(s: &'static str) -> Self {
        match s {
            "Failed to allocate heap frames" => Self::FrameAllocationFailed,
            "Failed to map heap page" => Self::MappingFailed,
            _ => Self::OutOfMemory,
        }
    }
}
