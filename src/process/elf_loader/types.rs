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

use alloc::string::String;
use alloc::vec::Vec;

pub use super::elf_constants::*;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Symbol {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Elf64Rela {
    pub fn symbol_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    pub fn relocation_type(&self) -> u32 {
        self.r_info as u32
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

#[derive(Debug, Clone)]
pub struct LoadedSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub flags: u32,
    pub file_offset: u64,
    pub filesz: u64,
}

impl LoadedSegment {
    /// Get the end address of this segment
    pub fn end_addr(&self) -> u64 {
        self.vaddr.saturating_add(self.memsz)
    }

    /// Check if this segment is readable
    pub fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }

    /// Check if this segment is writable
    pub fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    /// Check if this segment is executable
    pub fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    /// Get the BSS size (uninitialized data)
    pub fn bss_size(&self) -> u64 {
        self.memsz.saturating_sub(self.filesz)
    }

    /// Get file data parameters
    pub fn get_file_params(&self) -> (u64, u64) {
        (self.file_offset, self.filesz)
    }
}

#[derive(Debug)]
pub struct LoadedElf {
    pub entry: u64,
    pub base_addr: u64,
    pub phdr_addr: u64,
    pub phnum: u16,
    pub phentsize: u16,
    pub segments: Vec<LoadedSegment>,
    pub interp: Option<String>,
    pub exec_stack: bool,
    pub min_addr: u64,
    pub max_addr: u64,
    pub tls_addr: u64,
    pub tls_size: u64,
    pub tls_align: u64,
}

impl LoadedElf {
    /// Get the memory size of the loaded ELF
    pub fn memory_size(&self) -> u64 {
        self.max_addr.saturating_sub(self.min_addr)
    }

    /// Check if TLS is required
    pub fn has_tls(&self) -> bool {
        self.tls_size > 0
    }

    /// Get TLS configuration
    pub fn get_tls_config(&self) -> (u64, u64, u64) {
        (self.tls_addr, self.tls_size, self.tls_align)
    }

    /// Check if dynamic linker is required
    pub fn needs_interp(&self) -> bool {
        self.interp.is_some()
    }

    /// Get interpreter path if present
    pub fn get_interp(&self) -> Option<&str> {
        self.interp.as_deref()
    }

    /// Check if executable stack is allowed
    pub fn allows_exec_stack(&self) -> bool {
        self.exec_stack
    }

    /// Get program header information for auxiliary vector
    pub fn get_phdr_info(&self) -> (u64, u16, u16) {
        (self.phdr_addr, self.phnum, self.phentsize)
    }
}

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
            ElfError::TooSmall => write!(f, "ELF data too small"),
            ElfError::InvalidMagic => write!(f, "Invalid ELF magic number"),
            ElfError::Not64Bit => write!(f, "Not a 64-bit ELF"),
            ElfError::WrongEndian => write!(f, "Wrong endianness"),
            ElfError::WrongMachine => write!(f, "Unsupported machine type"),
            ElfError::NotExecutable => write!(f, "Not an executable"),
            ElfError::InvalidProgramHeader => write!(f, "Invalid program header"),
            ElfError::InvalidSectionHeader => write!(f, "Invalid section header"),
            ElfError::OverlappingSegments => write!(f, "Overlapping segments"),
            ElfError::InvalidAddress => write!(f, "Invalid address"),
            ElfError::WXViolation => write!(f, "W^X violation"),
            ElfError::AllocationFailed => write!(f, "Memory allocation failed"),
            ElfError::InvalidAlignment => write!(f, "Invalid alignment"),
            ElfError::RelocationFailed => write!(f, "Relocation failed"),
            ElfError::MissingSection => write!(f, "Missing required section"),
        }
    }
}
