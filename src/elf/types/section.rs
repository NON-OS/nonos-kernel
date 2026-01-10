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

use super::constants::{shdr_flags, shdr_type};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
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

impl SectionHeader {
    pub const SIZE: usize = 64;

    #[inline]
    pub fn is_alloc(&self) -> bool {
        self.sh_flags & shdr_flags::SHF_ALLOC != 0
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        self.sh_flags & shdr_flags::SHF_WRITE != 0
    }

    #[inline]
    pub fn is_executable(&self) -> bool {
        self.sh_flags & shdr_flags::SHF_EXECINSTR != 0
    }

    #[inline]
    pub fn is_bss(&self) -> bool {
        self.sh_type == shdr_type::SHT_NOBITS
    }

    pub fn type_name(&self) -> &'static str {
        match self.sh_type {
            shdr_type::SHT_NULL => "NULL",
            shdr_type::SHT_PROGBITS => "PROGBITS",
            shdr_type::SHT_SYMTAB => "SYMTAB",
            shdr_type::SHT_STRTAB => "STRTAB",
            shdr_type::SHT_RELA => "RELA",
            shdr_type::SHT_HASH => "HASH",
            shdr_type::SHT_DYNAMIC => "DYNAMIC",
            shdr_type::SHT_NOTE => "NOTE",
            shdr_type::SHT_NOBITS => "NOBITS",
            shdr_type::SHT_REL => "REL",
            shdr_type::SHT_DYNSYM => "DYNSYM",
            _ => "UNKNOWN",
        }
    }
}

impl Default for SectionHeader {
    fn default() -> Self {
        Self {
            sh_name: 0,
            sh_type: 0,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_section_header_size() {
        assert_eq!(mem::size_of::<SectionHeader>(), SectionHeader::SIZE);
    }
}
