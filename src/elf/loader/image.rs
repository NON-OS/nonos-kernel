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

use alloc::{string::String, vec::Vec};
use core::mem;
use x86_64::{structures::paging::PageTableFlags, VirtAddr};

use crate::elf::tls::TlsInfo;
use crate::elf::types::{phdr_type, RelaEntry};

#[derive(Debug)]
pub struct ElfImage {
    pub base_addr: VirtAddr,
    pub entry_point: VirtAddr,
    pub size: usize,
    pub segments: Vec<LoadedSegment>,
    pub dynamic_info: Option<DynamicInfo>,
    pub tls_info: Option<TlsInfo>,
    pub interpreter: Option<String>,
}

impl ElfImage {
    pub fn is_pie(&self) -> bool {
        self.interpreter.is_some() || self.dynamic_info.is_some()
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn has_dynamic_info(&self) -> bool {
        self.dynamic_info.is_some()
    }

    pub fn has_tls(&self) -> bool {
        self.tls_info.is_some()
    }

    pub fn requires_interpreter(&self) -> bool {
        self.interpreter.is_some()
    }

    pub fn memory_footprint(&self) -> usize {
        self.segments.iter().map(|s| s.size).sum()
    }
}

#[derive(Debug, Clone)]
pub struct LoadedSegment {
    pub vaddr: VirtAddr,
    pub size: usize,
    pub flags: PageTableFlags,
    pub segment_type: u32,
}

impl LoadedSegment {
    pub fn is_readable(&self) -> bool {
        self.flags.contains(PageTableFlags::PRESENT)
    }

    pub fn is_writable(&self) -> bool {
        self.flags.contains(PageTableFlags::WRITABLE)
    }

    pub fn is_executable(&self) -> bool {
        !self.flags.contains(PageTableFlags::NO_EXECUTE)
    }

    pub fn end_addr(&self) -> VirtAddr {
        self.vaddr + self.size as u64
    }

    pub fn type_name(&self) -> &'static str {
        match self.segment_type {
            phdr_type::PT_LOAD => "LOAD",
            phdr_type::PT_DYNAMIC => "DYNAMIC",
            phdr_type::PT_INTERP => "INTERP",
            phdr_type::PT_NOTE => "NOTE",
            phdr_type::PT_TLS => "TLS",
            phdr_type::PT_GNU_EH_FRAME => "EH_FRAME",
            phdr_type::PT_GNU_STACK => "GNU_STACK",
            phdr_type::PT_GNU_RELRO => "RELRO",
            _ => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DynamicInfo {
    pub needed_libraries: Vec<String>,
    pub symbol_table: Option<VirtAddr>,
    pub string_table: Option<VirtAddr>,
    pub string_table_size: usize,
    pub rela_table: Option<VirtAddr>,
    pub rela_size: usize,
    pub plt_relocations: Option<VirtAddr>,
    pub plt_rela_size: usize,
    pub init_function: Option<VirtAddr>,
    pub fini_function: Option<VirtAddr>,
}

impl DynamicInfo {
    pub fn new() -> Self {
        Self {
            needed_libraries: Vec::new(),
            symbol_table: None,
            string_table: None,
            string_table_size: 0,
            rela_table: None,
            rela_size: 0,
            plt_relocations: None,
            plt_rela_size: 0,
            init_function: None,
            fini_function: None,
        }
    }

    pub fn needs_relocation(&self) -> bool {
        self.rela_table.is_some() || self.plt_relocations.is_some()
    }

    pub fn needs_linking(&self) -> bool {
        !self.needed_libraries.is_empty()
    }

    pub fn rela_count(&self) -> usize {
        self.rela_size / mem::size_of::<RelaEntry>()
    }

    pub fn plt_rela_count(&self) -> usize {
        self.plt_rela_size / mem::size_of::<RelaEntry>()
    }
}

impl Default for DynamicInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_info_new() {
        let info = DynamicInfo::new();
        assert!(info.needed_libraries.is_empty());
        assert!(info.symbol_table.is_none());
        assert!(info.string_table.is_none());
        assert_eq!(info.string_table_size, 0);
        assert!(!info.needs_relocation());
        assert!(!info.needs_linking());
    }

    #[test]
    fn test_dynamic_info_rela_count() {
        let mut info = DynamicInfo::new();
        info.rela_size = 72;
        assert_eq!(info.rela_count(), 3);
    }

    #[test]
    fn test_loaded_segment_type_name() {
        let segment = LoadedSegment {
            vaddr: VirtAddr::new(0x1000),
            size: 4096,
            flags: PageTableFlags::PRESENT,
            segment_type: phdr_type::PT_LOAD,
        };
        assert_eq!(segment.type_name(), "LOAD");
    }

    #[test]
    fn test_loaded_segment_permissions() {
        let segment = LoadedSegment {
            vaddr: VirtAddr::new(0x1000),
            size: 4096,
            flags: PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            segment_type: phdr_type::PT_LOAD,
        };
        assert!(segment.is_readable());
        assert!(segment.is_writable());
        assert!(segment.is_executable());
    }

    #[test]
    fn test_loaded_segment_end_addr() {
        let segment = LoadedSegment {
            vaddr: VirtAddr::new(0x1000),
            size: 4096,
            flags: PageTableFlags::PRESENT,
            segment_type: phdr_type::PT_LOAD,
        };
        assert_eq!(segment.end_addr(), VirtAddr::new(0x2000));
    }
}
