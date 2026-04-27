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

use super::parser::get_program_headers;
use super::symbols::resolve_symbol;
use super::types::*;
use core::mem::size_of;

pub fn apply_relocations(
    data: &[u8],
    header: &Elf64Header,
    base_addr: u64,
) -> Result<(), ElfError> {
    let phdrs = get_program_headers(data, header)?;
    let dynamic_phdr = match phdrs.iter().find(|p| p.p_type == PT_DYNAMIC) {
        Some(phdr) => phdr,
        None => return Ok(()),
    };
    let dyn_offset = dynamic_phdr.p_offset as usize;
    let dyn_size = dynamic_phdr.p_filesz as usize;
    if dyn_offset + dyn_size > data.len() {
        return Err(ElfError::InvalidProgramHeader);
    }
    let num_entries = dyn_size / size_of::<Elf64Dyn>();
    let dyn_entries = unsafe {
        core::slice::from_raw_parts(data.as_ptr().add(dyn_offset) as *const Elf64Dyn, num_entries)
    };
    let mut rela_addr = 0u64;
    let mut rela_size = 0u64;
    let mut rela_ent = 0u64;
    let mut symtab = 0u64;
    let mut strtab = 0u64;
    let mut jmprel = 0u64;
    let mut pltrelsz = 0u64;
    for dyn_entry in dyn_entries {
        match dyn_entry.d_tag {
            DT_NULL => break,
            DT_RELA => rela_addr = dyn_entry.d_val,
            DT_RELASZ => rela_size = dyn_entry.d_val,
            DT_RELAENT => rela_ent = dyn_entry.d_val,
            DT_SYMTAB => symtab = dyn_entry.d_val,
            DT_STRTAB => strtab = dyn_entry.d_val,
            DT_JMPREL => jmprel = dyn_entry.d_val,
            DT_PLTRELSZ => pltrelsz = dyn_entry.d_val,
            _ => {}
        }
    }
    if rela_addr != 0 && rela_size != 0 {
        if rela_ent != size_of::<Elf64Rela>() as u64 {
            return Err(ElfError::RelocationFailed);
        }
        apply_rela_section(base_addr, rela_addr, rela_size, symtab, strtab)?;
    }
    if jmprel != 0 && pltrelsz != 0 {
        apply_rela_section(base_addr, jmprel, pltrelsz, symtab, strtab)?;
    }
    Ok(())
}

fn apply_rela_section(
    base: u64,
    rela_addr: u64,
    rela_size: u64,
    symtab: u64,
    strtab: u64,
) -> Result<(), ElfError> {
    let num_relas = (rela_size / size_of::<Elf64Rela>() as u64) as usize;
    let rela_ptr = (rela_addr + base) as *const Elf64Rela;
    for i in 0..num_relas {
        let rela = unsafe { &*rela_ptr.add(i) };
        let rel_type = rela.relocation_type();
        let sym_idx = rela.symbol_index();
        let target = (rela.r_offset + base) as *mut u64;
        match rel_type {
            R_X86_64_NONE => {}
            R_X86_64_RELATIVE => {
                let value = base.wrapping_add(rela.r_addend as u64);
                unsafe { core::ptr::write_volatile(target, value) };
            }
            R_X86_64_64 => {
                let sym_val = resolve_symbol(base, symtab, strtab, sym_idx)?;
                let value = sym_val.wrapping_add(rela.r_addend as u64);
                unsafe { core::ptr::write_volatile(target, value) };
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                let sym_val = resolve_symbol(base, symtab, strtab, sym_idx)?;
                unsafe { core::ptr::write_volatile(target, sym_val) };
            }
            R_X86_64_PC32 => {
                let sym_val = resolve_symbol(base, symtab, strtab, sym_idx)?;
                let value =
                    sym_val.wrapping_add(rela.r_addend as u64).wrapping_sub(rela.r_offset + base);
                unsafe { core::ptr::write_volatile(target as *mut u32, value as u32) };
            }
            R_X86_64_COPY => {
                let sym_val = resolve_symbol(base, symtab, strtab, sym_idx)?;
                let sym_ptr = (symtab + base + (sym_idx as u64) * size_of::<Elf64Symbol>() as u64)
                    as *const Elf64Symbol;
                let sym = unsafe { &*sym_ptr };
                if sym.st_size > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            sym_val as *const u8,
                            target as *mut u8,
                            sym.st_size as usize,
                        )
                    };
                }
            }
            _ => {}
        }
    }
    Ok(())
}
