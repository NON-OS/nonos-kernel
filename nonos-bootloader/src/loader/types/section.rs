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

use super::constants::sh_type;

pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_TLS: u64 = 0x400;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Shdr {
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

impl Elf64Shdr {
    pub fn is_null(&self) -> bool {
        self.sh_type == sh_type::SHT_NULL
    }

    pub fn is_progbits(&self) -> bool {
        self.sh_type == sh_type::SHT_PROGBITS
    }

    pub fn is_symtab(&self) -> bool {
        self.sh_type == sh_type::SHT_SYMTAB
    }

    pub fn is_strtab(&self) -> bool {
        self.sh_type == sh_type::SHT_STRTAB
    }

    pub fn is_rela(&self) -> bool {
        self.sh_type == sh_type::SHT_RELA
    }

    pub fn is_rel(&self) -> bool {
        self.sh_type == sh_type::SHT_REL
    }

    pub fn is_dynamic(&self) -> bool {
        self.sh_type == sh_type::SHT_DYNAMIC
    }

    pub fn is_nobits(&self) -> bool {
        self.sh_type == sh_type::SHT_NOBITS
    }

    pub fn is_dynsym(&self) -> bool {
        self.sh_type == sh_type::SHT_DYNSYM
    }

    pub fn is_writable(&self) -> bool {
        self.sh_flags & SHF_WRITE != 0
    }

    pub fn is_alloc(&self) -> bool {
        self.sh_flags & SHF_ALLOC != 0
    }

    pub fn is_executable(&self) -> bool {
        self.sh_flags & SHF_EXECINSTR != 0
    }

    pub fn is_tls(&self) -> bool {
        self.sh_flags & SHF_TLS != 0
    }

    pub fn end_offset(&self) -> u64 {
        self.sh_offset + self.sh_size
    }

    pub fn end_addr(&self) -> u64 {
        self.sh_addr + self.sh_size
    }
}
