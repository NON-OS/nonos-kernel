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

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;

pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Elf64Sym {
    pub fn binding(&self) -> u8 {
        self.st_info >> 4
    }

    pub fn sym_type(&self) -> u8 {
        self.st_info & 0xf
    }

    pub fn visibility(&self) -> u8 {
        self.st_other & 0x3
    }

    pub fn is_undefined(&self) -> bool {
        self.st_shndx == SHN_UNDEF
    }

    pub fn is_absolute(&self) -> bool {
        self.st_shndx == SHN_ABS
    }

    pub fn is_common(&self) -> bool {
        self.st_shndx == SHN_COMMON
    }

    pub fn is_local(&self) -> bool {
        self.binding() == STB_LOCAL
    }

    pub fn is_global(&self) -> bool {
        self.binding() == STB_GLOBAL
    }

    pub fn is_weak(&self) -> bool {
        self.binding() == STB_WEAK
    }

    pub fn is_function(&self) -> bool {
        self.sym_type() == STT_FUNC
    }

    pub fn is_object(&self) -> bool {
        self.sym_type() == STT_OBJECT
    }

    pub fn is_section(&self) -> bool {
        self.sym_type() == STT_SECTION
    }

    pub fn is_tls(&self) -> bool {
        self.sym_type() == STT_TLS
    }

    pub fn is_hidden(&self) -> bool {
        self.visibility() == STV_HIDDEN
    }

    pub fn is_protected(&self) -> bool {
        self.visibility() == STV_PROTECTED
    }
}

pub const fn elf64_st_info(binding: u8, sym_type: u8) -> u8 {
    (binding << 4) | (sym_type & 0xf)
}
