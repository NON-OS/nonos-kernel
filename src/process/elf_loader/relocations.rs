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

use core::mem::size_of;
use super::types::*;
use super::parser::get_program_headers;

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
    // SAFETY: We verified above that dyn_offset + dyn_size <= data.len(), so the
    // pointer arithmetic stays within bounds. Elf64Dyn is repr(C) with primitive
    // types only. The slice is valid for the lifetime of the input data.
    let dyn_entries = unsafe {
        core::slice::from_raw_parts(
            data.as_ptr().add(dyn_offset) as *const Elf64Dyn,
            num_entries,
        )
    };

    let mut rela_addr = 0u64;
    let mut rela_size = 0u64;
    let mut rela_ent = 0u64;

    for dyn_entry in dyn_entries {
        match dyn_entry.d_tag {
            DT_NULL => break,
            DT_RELA => rela_addr = dyn_entry.d_val,
            DT_RELASZ => rela_size = dyn_entry.d_val,
            DT_RELAENT => rela_ent = dyn_entry.d_val,
            _ => {}
        }
    }

    if rela_addr == 0 || rela_size == 0 {
        return Ok(());
    }

    if rela_ent != size_of::<Elf64Rela>() as u64 {
        return Err(ElfError::RelocationFailed);
    }

    let num_relas = (rela_size / rela_ent) as usize;
    let rela_ptr = (rela_addr + base_addr) as *const Elf64Rela;

    for i in 0..num_relas {
        // SAFETY: rela_addr comes from the DYNAMIC segment and points into loaded
        // memory. We verified rela_ent == size_of::<Elf64Rela>() above. The loop
        // bounds ensure i < num_relas which keeps us within the relocation section.
        let rela = unsafe { &*rela_ptr.add(i) };
        let rel_type = rela.relocation_type();

        match rel_type {
            R_X86_64_RELATIVE => {
                let target = (rela.r_offset + base_addr) as *mut u64;
                let value = base_addr.wrapping_add(rela.r_addend as u64);
                // SAFETY: The target address is within the loaded ELF image's memory
                // region (validated by the ELF loader). write_volatile is used to
                // ensure the write is not elided and to handle potential page sharing.
                unsafe { core::ptr::write_volatile(target, value) };
            }

            R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                crate::log::log_warning!("[ELF] Unresolved relocation type {}", rel_type);
            }

            R_X86_64_NONE => {}

            _ => {
                crate::log::log_warning!("[ELF] Unknown relocation type {}", rel_type);
            }
        }
    }

    Ok(())
}
