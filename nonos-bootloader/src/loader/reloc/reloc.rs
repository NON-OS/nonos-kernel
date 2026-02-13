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

use crate::loader::errors::LoaderError;
use crate::log::logger::{log_debug, log_error, log_info};

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
        // ## SAFETY: Caller ensures dyn_ptr points to valid dynamic section
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

pub fn process_relocations(ctx: &RelocationContext) -> Result<usize, LoaderError> {
    let mut reloc_count = 0;
    if let Some(rela_addr) = ctx.rela_addr {
        if ctx.rela_size > 0 && ctx.rela_ent > 0 {
            let entry_count = ctx.rela_size / ctx.rela_ent;
            log_debug("reloc", "Processing RELA relocations");

            for i in 0..entry_count {
                // ## SAFETY: rela_addr points to valid relocation table
                let rela = unsafe {
                    let ptr = (rela_addr as *const u8).add(i * ctx.rela_ent) as *const Rela64;
                    &*ptr
                };

                apply_relocation(rela, ctx)?;
                reloc_count += 1;
            }
        }
    }

    if let Some(jmprel_addr) = ctx.jmprel_addr {
        if ctx.jmprel_size > 0 && ctx.rela_ent > 0 {
            let entry_count = ctx.jmprel_size / ctx.rela_ent;
            log_debug("reloc", "Processing PLT relocations");

            for i in 0..entry_count {
                // ## SAFETY: jmprel_addr points to valid relocation table
                let rela = unsafe {
                    let ptr = (jmprel_addr as *const u8).add(i * ctx.rela_ent) as *const Rela64;
                    &*ptr
                };

                apply_relocation(rela, ctx)?;
                reloc_count += 1;
            }
        }
    }

    if reloc_count > 0 {
        log_info("reloc", "Relocations processed successfully");
    }

    Ok(reloc_count)
}

fn apply_relocation(rela: &Rela64, ctx: &RelocationContext) -> Result<(), LoaderError> {
    let reloc_type = rela.reloc_type();
    let target_addr = ctx.base_addr.wrapping_add(rela.r_offset);
    let addend = rela.r_addend;
    // ## SAFETY: target_addr is within the loaded image bounds
    unsafe {
        match reloc_type {
            reloc_type::R_X86_64_NONE => {}
            reloc_type::R_X86_64_RELATIVE => {
                let value = (ctx.base_addr as i64).wrapping_add(addend) as u64;
                let target_ptr = target_addr as *mut u64;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_64 => {
                let target_ptr = target_addr as *mut u64;
                *target_ptr = (*target_ptr).wrapping_add(ctx.load_bias as u64);
            }
            reloc_type::R_X86_64_GLOB_DAT | reloc_type::R_X86_64_JUMP_SLOT => {
                let target_ptr = target_addr as *mut u64;
                *target_ptr = (*target_ptr).wrapping_add(ctx.load_bias as u64);
            }
            reloc_type::R_X86_64_PC32 | reloc_type::R_X86_64_PLT32 => {}
            reloc_type::R_X86_64_32 => {
                let target_ptr = target_addr as *mut u32;
                let value = (*target_ptr as i64).wrapping_add(ctx.load_bias) as u32;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_32S => {
                let target_ptr = target_addr as *mut i32;
                let value = (*target_ptr as i64).wrapping_add(ctx.load_bias) as i32;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_IRELATIVE => {
                let value = (ctx.base_addr as i64).wrapping_add(addend) as u64;
                let target_ptr = target_addr as *mut u64;
                *target_ptr = value;
            }
            _ => {
                log_error("reloc", "Unsupported relocation type");
                return Err(LoaderError::MalformedElf("unsupported relocation type"));
            }
        }
    }

    Ok(())
}

pub fn process_elf_relocations(
    elf: &goblin::elf::Elf,
    base_addr: u64,
    load_bias: i64,
    payload: &[u8],
) -> Result<usize, LoaderError> {
    use goblin::elf::program_header::PT_DYNAMIC;

    let dynamic_ph = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_DYNAMIC);

    let dynamic_ph = match dynamic_ph {
        Some(ph) => ph,
        None => {
            log_debug("reloc", "No PT_DYNAMIC segment, skipping relocations");
            return Ok(0);
        }
    };

    let dyn_offset = dynamic_ph.p_offset as usize;
    let dyn_size = dynamic_ph.p_filesz as usize;

    if dyn_offset + dyn_size > payload.len() {
        return Err(LoaderError::SegmentOutOfBounds);
    }

    let mut ctx = RelocationContext::new(base_addr, load_bias);

    let dyn_entry_size = core::mem::size_of::<Dyn64>();
    let dyn_count = dyn_size / dyn_entry_size;

    // ## SAFETY: We've validated bounds above ^
    let dyn_ptr = unsafe { payload.as_ptr().add(dyn_offset) as *const Dyn64 };
    ctx.parse_dynamic(dyn_ptr, dyn_count);

    process_relocations(&ctx)
}
