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

use super::constants::{elf_class, elf_data, elf_machine, elf_type, ELF_MAGIC};

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

impl Elf64Header {
    pub fn is_valid(&self) -> bool {
        self.e_ident[0..4] == ELF_MAGIC
            && self.e_ident[4] == elf_class::ELFCLASS64
            && self.e_ident[5] == elf_data::ELFDATA2LSB
    }

    pub fn is_executable(&self) -> bool {
        self.e_type == elf_type::ET_EXEC || self.e_type == elf_type::ET_DYN
    }

    pub fn is_x86_64(&self) -> bool {
        self.e_machine == elf_machine::EM_X86_64
    }

    pub fn is_pie(&self) -> bool {
        self.e_type == elf_type::ET_DYN
    }
}
