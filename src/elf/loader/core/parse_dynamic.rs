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
use alloc::{string::String, vec::Vec};
use core::ptr;
use x86_64::VirtAddr;
use crate::elf::errors::ElfError;
use crate::elf::tls::TlsInfo;
use crate::elf::types::*;
use super::super::image::DynamicInfo;

pub(super) fn parse_dynamic_section(elf_data: &[u8], ph: &ProgramHeader, base_addr: VirtAddr) -> Result<DynamicInfo, ElfError> {
    let (mut dynamic_info, file_offset, entry_count) = (DynamicInfo::new(), ph.p_offset as usize, (ph.p_filesz as usize) / DynamicEntry::SIZE);
    let (mut needed_offsets, mut strtab_offset): (Vec<u64>, Option<u64>) = (Vec::new(), None);
    for i in 0..entry_count {
        let entry_offset = file_offset + (i * DynamicEntry::SIZE);
        if entry_offset + DynamicEntry::SIZE > elf_data.len() { break; }
        unsafe {
            let entry = ptr::read(elf_data[entry_offset..].as_ptr() as *const DynamicEntry);
            match entry.d_tag {
                0 => break, 1 => needed_offsets.push(entry.value),
                5 => { dynamic_info.string_table = Some(base_addr + entry.value); strtab_offset = Some(entry.value); }
                10 => dynamic_info.string_table_size = entry.value as usize, 6 => dynamic_info.symbol_table = Some(base_addr + entry.value),
                7 => dynamic_info.rela_table = Some(base_addr + entry.value), 8 => dynamic_info.rela_size = entry.value as usize,
                23 => dynamic_info.plt_relocations = Some(base_addr + entry.value), 2 => dynamic_info.plt_rela_size = entry.value as usize,
                12 => dynamic_info.init_function = Some(base_addr + entry.value), 13 => dynamic_info.fini_function = Some(base_addr + entry.value),
                _ => {}
            }
        }
    }
    if let Some(strtab_file_offset) = strtab_offset {
        for &name_offset in &needed_offsets {
            if let Some(string_offset) = (strtab_file_offset as usize).checked_add(name_offset as usize) {
                if string_offset < elf_data.len() { let name = read_string_from_data(elf_data, string_offset); if !name.is_empty() { dynamic_info.needed_libraries.push(name); } }
            }
        }
    }
    Ok(dynamic_info)
}

pub(super) fn parse_tls_section(ph: &ProgramHeader, base_addr: VirtAddr) -> Result<TlsInfo, ElfError> {
    Ok(TlsInfo { template_addr: base_addr + ph.p_vaddr, template_size: ph.p_filesz as usize, memory_size: ph.p_memsz as usize, alignment: ph.p_align as usize })
}

pub(super) fn parse_interpreter(elf_data: &[u8], ph: &ProgramHeader) -> Result<String, ElfError> {
    let (file_offset, size) = (ph.p_offset as usize, ph.p_filesz as usize);
    if file_offset + size > elf_data.len() { return Err(ElfError::InterpreterNotFound); }
    let path_bytes = &elf_data[file_offset..file_offset + size];
    let null_pos = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
    core::str::from_utf8(&path_bytes[..null_pos]).map(Into::into).map_err(|_| ElfError::InterpreterInvalidUtf8)
}

pub(super) fn read_string_from_data(data: &[u8], offset: usize) -> String {
    let mut result = String::new();
    let mut pos = offset;
    while pos < data.len() && data[pos] != 0 && result.len() < 256 { result.push(data[pos] as char); pos += 1; }
    result
}
