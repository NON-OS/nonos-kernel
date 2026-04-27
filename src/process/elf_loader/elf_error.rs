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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooSmall,
    InvalidMagic,
    Not64Bit,
    WrongEndian,
    WrongMachine,
    NotExecutable,
    InvalidProgramHeader,
    InvalidSectionHeader,
    OverlappingSegments,
    InvalidAddress,
    WXViolation,
    AllocationFailed,
    InvalidAlignment,
    RelocationFailed,
    MissingSection,
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "ELF data too small"),
            Self::InvalidMagic => write!(f, "Invalid ELF magic number"),
            Self::Not64Bit => write!(f, "Not a 64-bit ELF"),
            Self::WrongEndian => write!(f, "Wrong endianness"),
            Self::WrongMachine => write!(f, "Unsupported machine type"),
            Self::NotExecutable => write!(f, "Not an executable"),
            Self::InvalidProgramHeader => write!(f, "Invalid program header"),
            Self::InvalidSectionHeader => write!(f, "Invalid section header"),
            Self::OverlappingSegments => write!(f, "Overlapping segments"),
            Self::InvalidAddress => write!(f, "Invalid address"),
            Self::WXViolation => write!(f, "W^X violation"),
            Self::AllocationFailed => write!(f, "Memory allocation failed"),
            Self::InvalidAlignment => write!(f, "Invalid alignment"),
            Self::RelocationFailed => write!(f, "Relocation failed"),
            Self::MissingSection => write!(f, "Missing required section"),
        }
    }
}
