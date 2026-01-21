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

use super::constants::tag;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultibootError {
    InvalidMagic { expected: u32, found: u32 },
    InvalidInfoSize { size: u32 },
    MalformedTag { tag_type: u32, reason: &'static str },
    MemoryMapError { reason: &'static str },
    FramebufferError { reason: &'static str },
    ModuleError { reason: &'static str },
    ElfSectionError { reason: &'static str },
    AcpiError { reason: &'static str },
    SmbiosError { reason: &'static str },
    NotInitialized,
    AlreadyInitialized,
    NoMemoryMap,
    InvalidUtf8,
    AlignmentError { expected: usize, found: usize },
    AddressOutOfRange { address: u64 },
}

impl MultibootError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidMagic { .. } => "Invalid multiboot magic number",
            Self::InvalidInfoSize { .. } => "Invalid information structure size",
            Self::MalformedTag { .. } => "Malformed tag structure",
            Self::MemoryMapError { .. } => "Memory map parsing error",
            Self::FramebufferError { .. } => "Framebuffer info parsing error",
            Self::ModuleError { .. } => "Module parsing error",
            Self::ElfSectionError { .. } => "ELF section parsing error",
            Self::AcpiError { .. } => "ACPI RSDP parsing error",
            Self::SmbiosError { .. } => "SMBIOS parsing error",
            Self::NotInitialized => "Multiboot subsystem not initialized",
            Self::AlreadyInitialized => "Multiboot subsystem already initialized",
            Self::NoMemoryMap => "No memory map available",
            Self::InvalidUtf8 => "Invalid UTF-8 in string data",
            Self::AlignmentError { .. } => "Pointer alignment error",
            Self::AddressOutOfRange { .. } => "Address out of valid range",
        }
    }
}

impl core::fmt::Display for MultibootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMagic { expected, found } => {
                write!(f, "Invalid multiboot magic: expected 0x{:08X}, found 0x{:08X}", expected, found)
            }
            Self::InvalidInfoSize { size } => {
                write!(f, "Invalid information structure size: {} bytes", size)
            }
            Self::MalformedTag { tag_type, reason } => {
                write!(f, "Malformed tag type {}: {}", tag::name(*tag_type), reason)
            }
            Self::MemoryMapError { reason } => write!(f, "Memory map parsing error: {}", reason),
            Self::FramebufferError { reason } => write!(f, "Framebuffer parsing error: {}", reason),
            Self::ModuleError { reason } => write!(f, "Module parsing error: {}", reason),
            Self::ElfSectionError { reason } => write!(f, "ELF section parsing error: {}", reason),
            Self::AcpiError { reason } => write!(f, "ACPI RSDP parsing error: {}", reason),
            Self::SmbiosError { reason } => write!(f, "SMBIOS parsing error: {}", reason),
            Self::NotInitialized => write!(f, "Multiboot subsystem not initialized"),
            Self::AlreadyInitialized => write!(f, "Multiboot subsystem already initialized"),
            Self::NoMemoryMap => write!(f, "No memory map available from bootloader"),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 encoding in string data"),
            Self::AlignmentError { expected, found } => {
                write!(f, "Pointer alignment error: expected {}-byte alignment, found {} offset", expected, found)
            }
            Self::AddressOutOfRange { address } => {
                write!(f, "Address 0x{:016X} is out of valid range", address)
            }
        }
    }
}
