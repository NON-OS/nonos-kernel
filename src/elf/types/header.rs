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

use super::constants::{class, data, elf_type, ident, machine, ELF_MAGIC};
use super::program::ProgramHeader;
use super::section::SectionHeader;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ElfHeader {
    pub ident: [u8; 16],
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

impl ElfHeader {
    pub const SIZE: usize = 64;

    #[inline]
    pub fn is_valid_magic(&self) -> bool {
        self.ident[0..4] == ELF_MAGIC
    }

    #[inline]
    pub fn is_64bit(&self) -> bool {
        self.ident[ident::EI_CLASS] == class::ELFCLASS64
    }

    #[inline]
    pub fn is_little_endian(&self) -> bool {
        self.ident[ident::EI_DATA] == data::ELFDATA2LSB
    }

    #[inline]
    pub fn is_executable(&self) -> bool {
        self.e_type == elf_type::ET_EXEC || self.e_type == elf_type::ET_DYN
    }

    #[inline]
    pub fn is_pie(&self) -> bool {
        self.e_type == elf_type::ET_DYN
    }

    #[inline]
    pub fn is_x86_64(&self) -> bool {
        self.e_machine == machine::EM_X86_64
    }

    pub fn type_name(&self) -> &'static str {
        match self.e_type {
            elf_type::ET_NONE => "NONE",
            elf_type::ET_REL => "REL",
            elf_type::ET_EXEC => "EXEC",
            elf_type::ET_DYN => "DYN",
            elf_type::ET_CORE => "CORE",
            _ => "UNKNOWN",
        }
    }

    pub fn machine_name(&self) -> &'static str {
        match self.e_machine {
            machine::EM_NONE => "None",
            machine::EM_386 => "Intel 80386",
            machine::EM_X86_64 => "AMD x86-64",
            machine::EM_AARCH64 => "AArch64",
            machine::EM_RISCV => "RISC-V",
            _ => "Unknown",
        }
    }
}

impl Default for ElfHeader {
    fn default() -> Self {
        Self {
            ident: [0; 16],
            e_type: 0,
            e_machine: 0,
            e_version: 0,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: Self::SIZE as u16,
            e_phentsize: ProgramHeader::SIZE as u16,
            e_phnum: 0,
            e_shentsize: SectionHeader::SIZE as u16,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_elf_header_size() {
        assert_eq!(mem::size_of::<ElfHeader>(), ElfHeader::SIZE);
    }

    #[test]
    fn test_elf_magic() {
        let mut header = ElfHeader::default();
        assert!(!header.is_valid_magic());

        header.ident[0..4].copy_from_slice(&ELF_MAGIC);
        assert!(header.is_valid_magic());
    }

    #[test]
    fn test_elf_header_helpers() {
        let mut header = ElfHeader::default();
        header.ident[ident::EI_CLASS] = class::ELFCLASS64;
        header.ident[ident::EI_DATA] = data::ELFDATA2LSB;
        header.e_type = elf_type::ET_DYN;
        header.e_machine = machine::EM_X86_64;

        assert!(header.is_64bit());
        assert!(header.is_little_endian());
        assert!(header.is_executable());
        assert!(header.is_pie());
        assert!(header.is_x86_64());
        assert_eq!(header.type_name(), "DYN");
        assert_eq!(header.machine_name(), "AMD x86-64");
    }
}
