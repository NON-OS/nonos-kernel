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

use super::constants::{ph_flags, ph_type};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Elf64Phdr {
    pub fn is_load(&self) -> bool {
        self.p_type == ph_type::PT_LOAD
    }

    pub fn is_dynamic(&self) -> bool {
        self.p_type == ph_type::PT_DYNAMIC
    }

    pub fn is_tls(&self) -> bool {
        self.p_type == ph_type::PT_TLS
    }

    pub fn is_gnu_relro(&self) -> bool {
        self.p_type == ph_type::PT_GNU_RELRO
    }

    pub fn is_gnu_stack(&self) -> bool {
        self.p_type == ph_type::PT_GNU_STACK
    }

    pub fn is_readable(&self) -> bool {
        self.p_flags & ph_flags::PF_R != 0
    }

    pub fn is_writable(&self) -> bool {
        self.p_flags & ph_flags::PF_W != 0
    }

    pub fn is_executable(&self) -> bool {
        self.p_flags & ph_flags::PF_X != 0
    }

    pub fn has_wx(&self) -> bool {
        self.is_writable() && self.is_executable()
    }

    pub fn bss_size(&self) -> u64 {
        if self.p_memsz > self.p_filesz {
            self.p_memsz - self.p_filesz
        } else {
            0
        }
    }

    pub fn end_vaddr(&self) -> u64 {
        self.p_vaddr + self.p_memsz
    }

    pub fn end_offset(&self) -> u64 {
        self.p_offset + self.p_filesz
    }
}
