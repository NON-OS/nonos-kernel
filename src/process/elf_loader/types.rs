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
