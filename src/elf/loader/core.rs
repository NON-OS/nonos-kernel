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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::ptr;
use x86_64::{structures::paging::PageTableFlags, VirtAddr};

use crate::elf::aslr::AslrManager;
use crate::elf::errors::ElfError;
use crate::elf::reloc::process_relocations;
use crate::elf::tls::TlsInfo;
use crate::elf::types::*;
use crate::memory::{frame_alloc, virtual_memory};

use super::image::{DynamicInfo, ElfImage, LoadedSegment};

#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub name: String,
    pub section_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub alignment: u64,
    pub entry_size: u64,
}

impl ParsedSection {
    pub fn is_alloc(&self) -> bool {
        self.flags & 0x2 != 0
    }

    pub fn is_symtab(&self) -> bool {
        self.section_type == 2 || self.section_type == 11
    }

    pub fn is_strtab(&self) -> bool {
        self.section_type == 3
    }

    pub fn is_rela(&self) -> bool {
        self.section_type == 4
    }
}

const DEFAULT_STATIC_BASE: u64 = 0x400000;
const DEFAULT_PIE_BASE: u64 = 0x400000;

pub struct ElfLoader {
    aslr_manager: AslrManager,
    loaded_libraries: BTreeMap<String, ElfImage>,
    symbol_cache: BTreeMap<String, VirtAddr>,
}

impl ElfLoader {
    pub fn new() -> Self {
        ElfLoader {
            aslr_manager: AslrManager::new(),
            loaded_libraries: BTreeMap::new(),
            symbol_cache: BTreeMap::new(),
        }
    }

    pub fn load_executable(&mut self, elf_data: &[u8]) -> Result<ElfImage, ElfError> {
        let header = self.parse_elf_header(elf_data)?;
        self.validate_elf(&header)?;

        let program_headers = self.parse_program_headers(elf_data, &header)?;

        let base_addr = if header.e_type == elf_type::ET_DYN {
            VirtAddr::new(self.aslr_manager.randomize_base(DEFAULT_PIE_BASE))
        } else {
            VirtAddr::new(DEFAULT_STATIC_BASE)
        };

        let mut loaded_segments = Vec::new();
        let mut dynamic_info = None;
        let mut tls_info = None;
        let mut interpreter = None;

        for ph in &program_headers {
            match ph.p_type {
                phdr_type::PT_LOAD => {
                    let segment = self.load_segment(elf_data, ph, base_addr)?;
                    loaded_segments.push(segment);
                }
                phdr_type::PT_DYNAMIC => {
                    dynamic_info = Some(self.parse_dynamic_section(elf_data, ph, base_addr)?);
                }
                phdr_type::PT_TLS => {
                    tls_info = Some(self.parse_tls_section(ph, base_addr)?);
                }
                phdr_type::PT_INTERP => {
                    interpreter = Some(self.parse_interpreter(elf_data, ph)?);
                }
                _ => {}
            }
        }

        let entry_point = if header.e_type == elf_type::ET_DYN {
            base_addr + header.e_entry
        } else {
            VirtAddr::new(header.e_entry)
        };

        let total_size = loaded_segments.iter().map(|seg| seg.size).sum();

        let image = ElfImage {
            base_addr,
            entry_point,
            size: total_size,
            segments: loaded_segments,
            dynamic_info,
            tls_info,
            interpreter,
        };

        if let Some(ref dyn_info) = image.dynamic_info {
            if dyn_info.needs_relocation() {
                self.process_image_relocations(&image, dyn_info)?;
            }
        }

        Ok(image)
    }

        fn parse_elf_header(&self, elf_data: &[u8]) -> Result<ElfHeader, ElfError> {
        if elf_data.len() < ElfHeader::SIZE {
            return Err(ElfError::FileTooSmall);
        }
        unsafe {
            let header_ptr = elf_data.as_ptr() as *const ElfHeader;
            Ok(ptr::read(header_ptr))
        }
    }

        fn validate_elf(&self, header: &ElfHeader) -> Result<(), ElfError> {
        if !header.is_valid_magic() {
            return Err(ElfError::InvalidMagic);
        }
        if !header.is_64bit() {
            return Err(ElfError::InvalidClass);
        }
        if !header.is_little_endian() {
            return Err(ElfError::InvalidEndian);
        }
        if header.ident[6] != 1 {
            return Err(ElfError::InvalidVersion);
        }
        if header.e_machine != elf_machine::EM_X86_64 {
            return Err(ElfError::InvalidMachine);
        }
        if header.e_type != elf_type::ET_EXEC && header.e_type != elf_type::ET_DYN {
            return Err(ElfError::InvalidType);
        }
        Ok(())
    }

        fn parse_program_headers(
        &self,
        elf_data: &[u8],
        header: &ElfHeader,
    ) -> Result<Vec<ProgramHeader>, ElfError> {
        let ph_offset = header.e_phoff as usize;
        let ph_size = header.e_phentsize as usize;
        let ph_count = header.e_phnum as usize;

        if ph_offset + (ph_size * ph_count) > elf_data.len() {
            return Err(ElfError::ProgramHeadersOutOfBounds);
        }

        let mut program_headers = Vec::with_capacity(ph_count);
        for i in 0..ph_count {
            let offset = ph_offset + (i * ph_size);
            unsafe {
                let ph_ptr = elf_data[offset..].as_ptr() as *const ProgramHeader;
                program_headers.push(ptr::read(ph_ptr));
            }
        }
        Ok(program_headers)
    }

        fn load_segment(
        &self,
        elf_data: &[u8],
        ph: &ProgramHeader,
        base_addr: VirtAddr,
    ) -> Result<LoadedSegment, ElfError> {
        let vaddr = base_addr + ph.p_vaddr;
        let size = ph.p_memsz as usize;
        let file_size = ph.p_filesz as usize;

        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if ph.is_writable() {
            flags |= PageTableFlags::WRITABLE;
        }
        if !ph.is_executable() {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        let pages_needed = (size + 0xFFF) >> 12;
        for i in 0..pages_needed {
            if let Some(_frame) = frame_alloc::allocate_frame() {
                let page_vaddr = vaddr + (i * 4096);
                let protection = self.flags_to_protection(flags);
                virtual_memory::map_memory_range(
                    page_vaddr,
                    4096,
                    protection,
                    crate::memory::virtual_memory::VmType::File,
                )?;
            } else {
                return Err(ElfError::MemoryAllocationFailed);
            }
        }

        if file_size > 0 {
            let file_offset = ph.p_offset as usize;
            if file_offset + file_size > elf_data.len() {
                return Err(ElfError::SegmentDataOutOfBounds);
            }
            unsafe {
                let src = elf_data[file_offset..file_offset + file_size].as_ptr();
                let dst = vaddr.as_mut_ptr::<u8>();
                ptr::copy_nonoverlapping(src, dst, file_size);

                if size > file_size {
                    ptr::write_bytes(dst.add(file_size), 0, size - file_size);
                }
            }
        } else if size > 0 {
            unsafe {
                let dst = vaddr.as_mut_ptr::<u8>();
                ptr::write_bytes(dst, 0, size);
            }
        }

        Ok(LoadedSegment {
            vaddr,
            size,
            flags,
            segment_type: ph.p_type,
        })
    }

        fn flags_to_protection(
        &self,
        flags: PageTableFlags,
    ) -> crate::memory::virtual_memory::VmProtection {
        if flags.contains(PageTableFlags::WRITABLE) {
            if flags.contains(PageTableFlags::NO_EXECUTE) {
                crate::memory::virtual_memory::VmProtection::ReadWrite
            } else {
                crate::memory::virtual_memory::VmProtection::ReadWriteExecute
            }
        } else if flags.contains(PageTableFlags::NO_EXECUTE) {
            crate::memory::virtual_memory::VmProtection::Read
        } else {
            crate::memory::virtual_memory::VmProtection::ReadExecute
        }
    }

        fn parse_dynamic_section(
        &self,
        elf_data: &[u8],
        ph: &ProgramHeader,
        base_addr: VirtAddr,
    ) -> Result<DynamicInfo, ElfError> {
        let mut dynamic_info = DynamicInfo::new();
        let file_offset = ph.p_offset as usize;
        let entry_count = (ph.p_filesz as usize) / DynamicEntry::SIZE;

        let mut needed_offsets: Vec<u64> = Vec::new();
        let mut strtab_offset: Option<u64> = None;

        for i in 0..entry_count {
            let entry_offset = file_offset + (i * DynamicEntry::SIZE);
            if entry_offset + DynamicEntry::SIZE > elf_data.len() {
                break;
            }

            unsafe {
                let entry_ptr = elf_data[entry_offset..].as_ptr() as *const DynamicEntry;
                let entry = ptr::read(entry_ptr);

                match entry.d_tag {
                    0 => break,
                    1 => needed_offsets.push(entry.value),
                    5 => {
                        dynamic_info.string_table = Some(base_addr + entry.value);
                        strtab_offset = Some(entry.value);
                    }
                    10 => dynamic_info.string_table_size = entry.value as usize,
                    6 => dynamic_info.symbol_table = Some(base_addr + entry.value),
                    7 => dynamic_info.rela_table = Some(base_addr + entry.value),
                    8 => dynamic_info.rela_size = entry.value as usize,
                    23 => dynamic_info.plt_relocations = Some(base_addr + entry.value),
                    2 => dynamic_info.plt_rela_size = entry.value as usize,
                    12 => dynamic_info.init_function = Some(base_addr + entry.value),
                    13 => dynamic_info.fini_function = Some(base_addr + entry.value),
                    _ => {}
                }
            }
        }

        if let Some(strtab_file_offset) = strtab_offset {
            for &name_offset in &needed_offsets {
                let string_offset = strtab_file_offset as usize + name_offset as usize;
                if string_offset < elf_data.len() {
                    let name = self.read_string_from_data(elf_data, string_offset);
                    if !name.is_empty() {
                        dynamic_info.needed_libraries.push(name);
                    }
                }
            }
        }

        Ok(dynamic_info)
    }

        fn read_string_from_data(&self, data: &[u8], offset: usize) -> String {
        let mut result = String::new();
        let mut pos = offset;
        while pos < data.len() && data[pos] != 0 {
            result.push(data[pos] as char);
            pos += 1;
            if result.len() >= 256 {
                break;
            }
        }
        result
    }

        pub fn parse_section_headers(
        &self,
        elf_data: &[u8],
    ) -> Result<Vec<ParsedSection>, ElfError> {
        let header = self.parse_elf_header(elf_data)?;

        if header.e_shoff == 0 || header.e_shnum == 0 {
            return Ok(Vec::new());
        }

        let sh_offset = header.e_shoff as usize;
        let sh_size = header.e_shentsize as usize;
        let sh_count = header.e_shnum as usize;
        let sh_strndx = header.e_shstrndx as usize;

        if sh_offset + (sh_size * sh_count) > elf_data.len() {
            return Err(ElfError::SectionHeadersOutOfBounds);
        }

        let shstrtab = if sh_strndx < sh_count && sh_strndx != 0 {
            let shstr_offset = sh_offset + (sh_strndx * sh_size);
            unsafe {
                let sh_ptr = elf_data[shstr_offset..].as_ptr() as *const SectionHeader;
                let sh = ptr::read(sh_ptr);
                Some((sh.sh_offset as usize, sh.sh_size as usize))
            }
        } else {
            None
        };

        let mut sections = Vec::with_capacity(sh_count);
        for i in 0..sh_count {
            let offset = sh_offset + (i * sh_size);
            unsafe {
                let sh_ptr = elf_data[offset..].as_ptr() as *const SectionHeader;
                let sh = ptr::read(sh_ptr);

                let name = if let Some((strtab_off, strtab_size)) = shstrtab {
                    let name_offset = strtab_off + sh.sh_name as usize;
                    if name_offset < strtab_off + strtab_size {
                        self.read_string_from_data(elf_data, name_offset)
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

        pub fn find_section_by_name<'a>(
        sections: &'a [ParsedSection],
        name: &str,
    ) -> Option<&'a ParsedSection> {
        sections.iter().find(|s| s.name == name)
    }

        pub fn get_symbol_table<'a>(
        sections: &'a [ParsedSection],
    ) -> Option<&'a ParsedSection> {
        sections.iter().find(|s| s.is_symtab())
    }

        pub fn get_dynsym<'a>(
        sections: &'a [ParsedSection],
    ) -> Option<&'a ParsedSection> {
        sections.iter().find(|s| s.section_type == 11)
    }

        fn parse_tls_section(
        &self,
        ph: &ProgramHeader,
        base_addr: VirtAddr,
    ) -> Result<TlsInfo, ElfError> {
        Ok(TlsInfo {
            template_addr: base_addr + ph.p_vaddr,
            template_size: ph.p_filesz as usize,
            memory_size: ph.p_memsz as usize,
            alignment: ph.p_align as usize,
        })
    }

        fn parse_interpreter(
        &self,
        elf_data: &[u8],
        ph: &ProgramHeader,
    ) -> Result<String, ElfError> {
        let file_offset = ph.p_offset as usize;
        let size = ph.p_filesz as usize;

        if file_offset + size > elf_data.len() {
            return Err(ElfError::InterpreterNotFound);
        }

        let path_bytes = &elf_data[file_offset..file_offset + size];
        let null_pos = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());

        core::str::from_utf8(&path_bytes[..null_pos])
            .map(Into::into)
            .map_err(|_| ElfError::InterpreterInvalidUtf8)
    }

        fn process_image_relocations(
        &self,
        image: &ElfImage,
        dyn_info: &DynamicInfo,
    ) -> Result<(), ElfError> {
        let mut rela_entries = Vec::new();

        if let Some(rela_addr) = dyn_info.rela_table {
            let entry_count = dyn_info.rela_count();
            let rela_ptr = rela_addr.as_u64() as *const RelaEntry;
            unsafe {
                for i in 0..entry_count {
                    rela_entries.push(ptr::read(rela_ptr.add(i)));
                }
            }
        }

        if let Some(plt_addr) = dyn_info.plt_relocations {
            let entry_count = dyn_info.plt_rela_count();
            let plt_ptr = plt_addr.as_u64() as *const RelaEntry;
            unsafe {
                for i in 0..entry_count {
                    rela_entries.push(ptr::read(plt_ptr.add(i)));
                }
            }
        }

        if !rela_entries.is_empty() {
            process_relocations(image, &rela_entries)?;
        }

        Ok(())
    }

        pub fn library_count(&self) -> usize {
        self.loaded_libraries.len()
    }

        pub fn symbol_count(&self) -> usize {
        self.symbol_cache.len()
    }

        pub fn clear_symbol_cache(&mut self) {
        self.symbol_cache.clear();
    }
}

impl Default for ElfLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_loader_new() {
        let loader = ElfLoader::new();
        assert_eq!(loader.library_count(), 0);
        assert_eq!(loader.symbol_count(), 0);
    }

    #[test]
    fn test_elf_loader_default() {
        let loader = ElfLoader::default();
        assert_eq!(loader.library_count(), 0);
    }

    #[test]
    fn test_validate_elf_invalid_magic() {
        let loader = ElfLoader::new();
        let header = ElfHeader {
            ident: [0; 16],
            ..Default::default()
        };
        assert!(matches!(loader.validate_elf(&header), Err(ElfError::InvalidMagic)));
    }

    #[test]
    fn test_validate_elf_invalid_class() {
        let loader = ElfLoader::new();
        let mut ident = [0u8; 16];
        ident[0..4].copy_from_slice(&ELF_MAGIC);
        ident[4] = elf_class::ELFCLASS32; // 32-bit
        let header = ElfHeader {
            ident,
            ..Default::default()
        };
        assert!(matches!(loader.validate_elf(&header), Err(ElfError::InvalidClass)));
    }

    #[test]
    fn test_parse_elf_header_too_small() {
        let loader = ElfLoader::new();
        let data = [0u8; 32]; // Too small for 64-byte header
        assert!(matches!(loader.parse_elf_header(&data), Err(ElfError::FileTooSmall)));
    }
}
