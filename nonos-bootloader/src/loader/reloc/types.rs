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

pub mod reloc_type {
    pub const R_X86_64_NONE: u32 = 0;
    pub const R_X86_64_64: u32 = 1;
    pub const R_X86_64_PC32: u32 = 2;
    pub const R_X86_64_GOT32: u32 = 3;
    pub const R_X86_64_PLT32: u32 = 4;
    pub const R_X86_64_COPY: u32 = 5;
    pub const R_X86_64_GLOB_DAT: u32 = 6;
    pub const R_X86_64_JUMP_SLOT: u32 = 7;
    pub const R_X86_64_RELATIVE: u32 = 8;
    pub const R_X86_64_GOTPCREL: u32 = 9;
    pub const R_X86_64_32: u32 = 10;
    pub const R_X86_64_32S: u32 = 11;
    pub const R_X86_64_16: u32 = 12;
    pub const R_X86_64_PC16: u32 = 13;
    pub const R_X86_64_8: u32 = 14;
    pub const R_X86_64_PC8: u32 = 15;
    pub const R_X86_64_IRELATIVE: u32 = 37;
}

pub mod dyn_tag {
    pub const DT_NULL: i64 = 0;
    pub const DT_RELA: i64 = 7;
    pub const DT_RELASZ: i64 = 8;
    pub const DT_RELAENT: i64 = 9;
    pub const DT_JMPREL: i64 = 23;
    pub const DT_PLTRELSZ: i64 = 2;
    pub const DT_PLTREL: i64 = 20;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Rela64 {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Rela64 {
    #[inline]
    pub fn reloc_type(&self) -> u32 {
        (self.r_info & 0xFFFFFFFF) as u32
    }

    #[inline]
    pub fn symbol_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Dyn64 {
    pub d_tag: i64,
    pub d_val: u64,
}

pub struct RelocationContext {
    pub base_addr: u64,
    pub load_bias: i64,
    pub rela_addr: Option<u64>,
    pub rela_size: usize,
    pub rela_ent: usize,
    pub jmprel_addr: Option<u64>,
    pub jmprel_size: usize,
}

impl RelocationContext {
    pub fn new(base_addr: u64, load_bias: i64) -> Self {
        Self {
            base_addr,
            load_bias,
            rela_addr: None,
            rela_size: 0,
            rela_ent: core::mem::size_of::<Rela64>(),
            jmprel_addr: None,
            jmprel_size: 0,
        }
    }

    pub fn parse_dynamic(&mut self, dyn_ptr: *const Dyn64, dyn_count: usize) {
        unsafe {
            for i in 0..dyn_count {
                let dyn_entry = &*dyn_ptr.add(i);

                if dyn_entry.d_tag == dyn_tag::DT_NULL {
                    break;
                }

                match dyn_entry.d_tag {
                    dyn_tag::DT_RELA => {
                        self.rela_addr = Some(self.base_addr + dyn_entry.d_val);
                    }
                    dyn_tag::DT_RELASZ => {
                        self.rela_size = dyn_entry.d_val as usize;
                    }
                    dyn_tag::DT_RELAENT => {
                        self.rela_ent = dyn_entry.d_val as usize;
                    }
                    dyn_tag::DT_JMPREL => {
                        self.jmprel_addr = Some(self.base_addr + dyn_entry.d_val);
                    }
                    dyn_tag::DT_PLTRELSZ => {
                        self.jmprel_size = dyn_entry.d_val as usize;
                    }
                    _ => {}
                }
            }
        }
    }
}
