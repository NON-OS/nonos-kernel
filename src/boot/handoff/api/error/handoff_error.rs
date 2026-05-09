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

use super::fb_geometry_reason::FbGeometryReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    NullPointer,
    InvalidMagic,
    VersionMismatch { expected: u16, got: u16 },
    SizeMismatch { expected: u16, got: u16 },
    AlreadyInitialized,
    InvalidData,
    WeakEntropy,
    MemoryMapEntrySize { expected: u32, got: u32 },
    FramebufferGeometry { reason: FbGeometryReason },
    EntryPointOutOfRange,
}

impl HandoffError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NullPointer => "Null handoff pointer",
            Self::InvalidMagic => "Invalid handoff magic value",
            Self::VersionMismatch { .. } => "Handoff version mismatch",
            Self::SizeMismatch { .. } => "Handoff size mismatch",
            Self::AlreadyInitialized => "Handoff already initialized",
            Self::InvalidData => "Invalid handoff data",
            Self::WeakEntropy => "Bootloader entropy seed is all zero",
            Self::MemoryMapEntrySize { .. } => "Memory map entry size mismatch",
            Self::FramebufferGeometry { .. } => "Framebuffer geometry rejected",
            Self::EntryPointOutOfRange => "Kernel entry point outside NØNOS image window",
        }
    }
}
