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

use super::types::*;
use super::parser::{parse_header, get_program_headers};
use super::validate::{validate_user_address, validate_wx_segment, validate_alignment};
use super::load_segment::{map_segment_pages, copy_segment_data};
use super::load_phdr::{load_interp, handle_gnu_stack, find_phdr_addr};

pub fn load_elf(data: &[u8], base_addr: u64) -> Result<LoadedElf, ElfError> {
    let header = parse_header(data)?;
    let phdrs = get_program_headers(data, header)?;
    let is_pie = header.e_type == ET_DYN;
    let actual_base = if is_pie { base_addr } else { 0 };
    let mut loaded = LoadedElf::new(header.e_entry + actual_base, actual_base, header.e_phnum, header.e_phentsize);
    for phdr in phdrs {
        if phdr.p_type != PT_LOAD { continue; }
        let vaddr = phdr.p_vaddr + actual_base;
        validate_user_address(vaddr, phdr.p_memsz)?;
        validate_wx_segment(phdr)?;
        validate_alignment(phdr)?;
    }
    for phdr in phdrs {
        process_phdr(data, phdr, actual_base, &mut loaded)?;
    }
    if loaded.phdr_addr == 0 { loaded.phdr_addr = find_phdr_addr(header, &loaded.segments); }
    crate::log::info!("[ELF] Loaded binary: segments={}, size={}KB",
        loaded.segments.len(), (loaded.max_addr.saturating_sub(loaded.min_addr)) / 1024);
    Ok(loaded)
}

fn process_phdr(data: &[u8], phdr: &Elf64ProgramHeader, base: u64, loaded: &mut LoadedElf) -> Result<(), ElfError> {
    match phdr.p_type {
        PT_LOAD => {
            let vaddr = phdr.p_vaddr + base;
            map_segment_pages(phdr, vaddr)?;
            copy_segment_data(data, phdr, vaddr)?;
            loaded.segments.push(LoadedSegment { vaddr, memsz: phdr.p_memsz, flags: phdr.p_flags,
                file_offset: phdr.p_offset, filesz: phdr.p_filesz });
            loaded.min_addr = loaded.min_addr.min(vaddr);
            loaded.max_addr = loaded.max_addr.max(vaddr + phdr.p_memsz);
        }
        PT_INTERP => { loaded.interp = Some(load_interp(data, phdr)?); }
        PT_PHDR => { loaded.phdr_addr = phdr.p_vaddr + base; }
        PT_GNU_STACK => { loaded.exec_stack = handle_gnu_stack(phdr); }
        PT_TLS => { loaded.tls_addr = phdr.p_vaddr + base; loaded.tls_size = phdr.p_memsz; loaded.tls_align = phdr.p_align; }
        _ => {}
    }
    Ok(())
}
