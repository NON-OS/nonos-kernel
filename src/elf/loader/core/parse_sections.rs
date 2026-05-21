// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::parse_dynamic::read_string_from_data;
use super::parse_header::parse_elf_header;
use super::section::ParsedSection;
use crate::elf::errors::ElfError;
use crate::elf::types::*;
use alloc::{string::String, vec::Vec};
use core::ptr;

pub(super) fn parse_section_headers(elf_data: &[u8]) -> Result<Vec<ParsedSection>, ElfError> {
    let header = parse_elf_header(elf_data)?;
    if header.e_shoff == 0 || header.e_shnum == 0 {
        return Ok(Vec::new());
    }
    let (sh_offset, sh_size, sh_count, sh_strndx) = (
        header.e_shoff as usize,
        header.e_shentsize as usize,
        header.e_shnum as usize,
        header.e_shstrndx as usize,
    );
    if sh_offset + (sh_size * sh_count) > elf_data.len() {
        return Err(ElfError::SectionHeadersOutOfBounds);
    }
    let shstrtab = if sh_strndx < sh_count && sh_strndx != 0 {
        unsafe {
            let sh = ptr::read_unaligned(
                elf_data[sh_offset + sh_strndx * sh_size..].as_ptr() as *const SectionHeader
            );
            Some((sh.sh_offset as usize, sh.sh_size as usize))
        }
    } else {
        None
    };
    let mut sections = Vec::with_capacity(sh_count);
    for i in 0..sh_count {
        unsafe {
            let sh = ptr::read_unaligned(
                elf_data[sh_offset + i * sh_size..].as_ptr() as *const SectionHeader
            );
            let name = if let Some((strtab_off, strtab_size)) = shstrtab {
                let name_offset = strtab_off + sh.sh_name as usize;
                if name_offset < strtab_off + strtab_size {
                    read_string_from_data(elf_data, name_offset)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            sections.push(ParsedSection {
                name,
                section_type: sh.sh_type,
                flags: sh.sh_flags,
                addr: sh.sh_addr,
                offset: sh.sh_offset,
                size: sh.sh_size,
                link: sh.sh_link,
                info: sh.sh_info,
                alignment: sh.sh_addralign,
                entry_size: sh.sh_entsize,
            });
        }
    }
    Ok(sections)
}
