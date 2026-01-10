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
    InvalidMagic,
    InvalidClass,
    InvalidEndian,
    InvalidVersion,
    InvalidMachine,
    InvalidType,
    FileTooSmall,
    ProgramHeadersOutOfBounds,
    SectionHeadersOutOfBounds,
    SegmentDataOutOfBounds,
    MemoryAllocationFailed,
    MemoryMappingFailed,
    RelocationFailed,
    UnsupportedRelocation(u32),
    InterpreterNotFound,
    InterpreterInvalidUtf8,
    TlsSectionError,
    DynamicSectionError,
    SymbolTableError,
    SymbolNotFound,
    StringTableError,
    StringTableOutOfBounds,
    UnknownFormat,
    NotInitialized,
    AddressOverflow,
    AlignmentError,
    InvalidIndex,
    InvalidHash,
    InvalidAddress,
    InvalidState,
    LibraryNotFound,
    LibraryAlreadyLoaded,
    CircularDependency,
    CacheFull,
    StackTooSmall,
    Other(&'static str),
}

impl ElfError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidMagic => "Invalid ELF magic number",
            Self::InvalidClass => "Invalid ELF class (not 64-bit)",
            Self::InvalidEndian => "Invalid ELF endianness (not little-endian)",
            Self::InvalidVersion => "Invalid ELF version",
            Self::InvalidMachine => "Invalid ELF machine type (not x86-64)",
            Self::InvalidType => "Invalid ELF type (not EXEC or DYN)",
            Self::FileTooSmall => "ELF file too small",
            Self::ProgramHeadersOutOfBounds => "Program headers out of bounds",
            Self::SectionHeadersOutOfBounds => "Section headers out of bounds",
            Self::SegmentDataOutOfBounds => "Segment data out of bounds",
            Self::MemoryAllocationFailed => "Memory allocation failed",
            Self::MemoryMappingFailed => "Memory mapping failed",
            Self::RelocationFailed => "Relocation processing failed",
            Self::UnsupportedRelocation(_) => "Unsupported relocation type",
            Self::InterpreterNotFound => "Interpreter not found",
            Self::InterpreterInvalidUtf8 => "Interpreter path not valid UTF-8",
            Self::TlsSectionError => "TLS section error",
            Self::DynamicSectionError => "Dynamic section error",
            Self::SymbolTableError => "Symbol table error",
            Self::SymbolNotFound => "Symbol not found",
            Self::StringTableError => "String table error",
            Self::StringTableOutOfBounds => "String table offset out of bounds",
            Self::UnknownFormat => "Unknown ELF format",
            Self::NotInitialized => "ELF loader not initialized",
            Self::AddressOverflow => "Address overflow",
            Self::AlignmentError => "Alignment requirements not met",
            Self::InvalidIndex => "Invalid index",
            Self::InvalidHash => "Invalid hash table",
            Self::InvalidAddress => "Invalid address",
            Self::InvalidState => "Invalid state",
            Self::LibraryNotFound => "Library not found",
            Self::LibraryAlreadyLoaded => "Library already loaded",
            Self::CircularDependency => "Circular dependency detected",
            Self::CacheFull => "Image cache full",
            Self::StackTooSmall => "Stack size too small",
            Self::Other(msg) => msg,
        }
    }

    pub const fn is_validation_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidMagic
                | Self::InvalidClass
                | Self::InvalidEndian
                | Self::InvalidVersion
                | Self::InvalidMachine
                | Self::InvalidType
        )
    }

    pub const fn is_bounds_error(&self) -> bool {
        matches!(
            self,
            Self::FileTooSmall
                | Self::ProgramHeadersOutOfBounds
                | Self::SectionHeadersOutOfBounds
                | Self::SegmentDataOutOfBounds
                | Self::StringTableOutOfBounds
        )
    }

    pub const fn is_memory_error(&self) -> bool {
        matches!(
            self,
            Self::MemoryAllocationFailed | Self::MemoryMappingFailed | Self::AddressOverflow
        )
    }

    pub const fn is_dynamic_error(&self) -> bool {
        matches!(
            self,
            Self::RelocationFailed
                | Self::UnsupportedRelocation(_)
                | Self::DynamicSectionError
                | Self::SymbolTableError
                | Self::SymbolNotFound
                | Self::StringTableError
        )
    }

    pub const fn is_library_error(&self) -> bool {
        matches!(
            self,
            Self::LibraryNotFound
                | Self::LibraryAlreadyLoaded
                | Self::CircularDependency
                | Self::CacheFull
        )
    }
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedRelocation(reloc_type) => {
                write!(f, "Unsupported relocation type: {}", reloc_type)
            }
            Self::Other(msg) => write!(f, "{}", msg),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}

impl From<&'static str> for ElfError {
    fn from(s: &'static str) -> Self {
        ElfError::Other(s)
    }
}

pub type ElfResult<T> = Result<T, ElfError>;
