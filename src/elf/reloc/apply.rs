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

extern crate alloc;

use alloc::collections::BTreeMap;

use crate::elf::errors::ElfError;
use crate::elf::loader::ElfImage;
use crate::elf::types::{reloc_type, RelaEntry};

use super::context::RelocationContext;

pub fn process_relocations_with_context(
    image: &ElfImage,
    rela_entries: &[RelaEntry],
    context: &RelocationContext,
) -> Result<(), ElfError> {
    for rela in rela_entries {
        apply_relocation_with_context(image, rela, context)?;
    }
    Ok(())
}

pub fn process_relocations(image: &ElfImage, rela_entries: &[RelaEntry]) -> Result<(), ElfError> {
    let empty_cache = BTreeMap::new();
    let context = if let Some(ref dyn_info) = image.dynamic_info {
        RelocationContext {
            symbol_table: dyn_info.symbol_table,
            string_table: dyn_info.string_table,
            string_table_size: dyn_info.string_table_size,
            got_base: None,
            symbol_cache: &empty_cache,
        }
    } else {
        RelocationContext::empty(&empty_cache)
    };

    process_relocations_with_context(image, rela_entries, &context)
}

fn apply_relocation_with_context(
    image: &ElfImage,
    rela: &RelaEntry,
    context: &RelocationContext,
) -> Result<(), ElfError> {
    let reloc_type_val = rela.reloc_type();
    let sym_index = rela.symbol_index();
    let target_addr = image
        .base_addr
        .as_u64()
        .checked_add(rela.r_offset)
        .ok_or(ElfError::AddressOverflow)?;

    let addend = rela.r_addend;
    let base = image.base_addr.as_u64();
    let symbol_value = if sym_index != 0 {
        context
            .resolve_symbol(sym_index, image.base_addr)
            .unwrap_or(0)
    } else {
        0
    };

    // SAFETY: Assumes validated segment mapping and sizes
    unsafe {
        match reloc_type_val {
            reloc_type::R_X86_64_NONE => {}
            reloc_type::R_X86_64_64 => {
                let value = (symbol_value as i64).wrapping_add(addend) as u64;
                let target_ptr = target_addr as *mut u64;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_PC32 => {
                let value = (symbol_value as i64)
                    .wrapping_add(addend)
                    .wrapping_sub(target_addr as i64);
                let target_ptr = target_addr as *mut i32;
                *target_ptr = value as i32;
            }
            reloc_type::R_X86_64_GOT32 => {
                if let Some(got) = context.got_base {
                    let got_offset = symbol_value.wrapping_sub(got.as_u64());
                    let value = (got_offset as i64).wrapping_add(addend) as i32;
                    let target_ptr = target_addr as *mut i32;
                    *target_ptr = value;
                } else {
                    return Err(ElfError::UnsupportedRelocation(reloc_type_val));
                }
            }
            reloc_type::R_X86_64_PLT32 => {
                let value = (symbol_value as i64)
                    .wrapping_add(addend)
                    .wrapping_sub(target_addr as i64);
                let target_ptr = target_addr as *mut i32;
                *target_ptr = value as i32;
            }
            reloc_type::R_X86_64_COPY => {
                if symbol_value != 0 {
                    return Err(ElfError::UnsupportedRelocation(reloc_type_val));
                }
            }
            reloc_type::R_X86_64_GLOB_DAT => {
                let target_ptr = target_addr as *mut u64;
                *target_ptr = symbol_value;
            }
            reloc_type::R_X86_64_JUMP_SLOT => {
                let target_ptr = target_addr as *mut u64;
                *target_ptr = symbol_value;
            }
            reloc_type::R_X86_64_RELATIVE => {
                let value = (base as i64).wrapping_add(addend) as u64;
                let target_ptr = target_addr as *mut u64;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_GOTPCREL => {
                if let Some(got) = context.got_base {
                    let value = (got.as_u64() as i64)
                        .wrapping_add(addend)
                        .wrapping_sub(target_addr as i64);
                    let target_ptr = target_addr as *mut i32;
                    *target_ptr = value as i32;
                } else {
                    return Err(ElfError::UnsupportedRelocation(reloc_type_val));
                }
            }
            reloc_type::R_X86_64_32 => {
                let value = (symbol_value as i64).wrapping_add(addend) as u32;
                let target_ptr = target_addr as *mut u32;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_32S => {
                let value = (symbol_value as i64).wrapping_add(addend) as i32;
                let target_ptr = target_addr as *mut i32;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_16 => {
                let value = (symbol_value as i64).wrapping_add(addend) as u16;
                let target_ptr = target_addr as *mut u16;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_PC16 => {
                let value = (symbol_value as i64)
                    .wrapping_add(addend)
                    .wrapping_sub(target_addr as i64) as i16;
                let target_ptr = target_addr as *mut i16;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_8 => {
                let value = (symbol_value as i64).wrapping_add(addend) as u8;
                let target_ptr = target_addr as *mut u8;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_PC8 => {
                let value = (symbol_value as i64)
                    .wrapping_add(addend)
                    .wrapping_sub(target_addr as i64) as i8;
                let target_ptr = target_addr as *mut i8;
                *target_ptr = value;
            }
            reloc_type::R_X86_64_IRELATIVE => {
                let resolver_addr = (base as i64).wrapping_add(addend) as u64;
                let resolver: extern "C" fn() -> u64 =
                    core::mem::transmute(resolver_addr as *const ());
                let resolved_value = resolver();
                let target_ptr = target_addr as *mut u64;
                *target_ptr = resolved_value;
            }
            _ => {
                return Err(ElfError::UnsupportedRelocation(reloc_type_val));
            }
        }
    }

    Ok(())
}
