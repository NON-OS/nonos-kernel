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

use super::constants::ph_flags;
use super::program::Elf64Phdr;

#[derive(Debug, Clone, Copy)]
pub struct LoadedSegment {
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub target_addr: u64,
    pub alignment: u64,
    pub flags: u32,
}

impl LoadedSegment {
    pub fn from_phdr(phdr: &Elf64Phdr) -> Self {
        Self {
            file_offset: phdr.p_offset,
            file_size: phdr.p_filesz,
            mem_size: phdr.p_memsz,
            target_addr: phdr.p_vaddr,
            alignment: phdr.p_align,
            flags: phdr.p_flags,
        }
    }

    pub fn is_readable(&self) -> bool {
        self.flags & ph_flags::PF_R != 0
    }

    pub fn is_writable(&self) -> bool {
        self.flags & ph_flags::PF_W != 0
    }

    pub fn is_executable(&self) -> bool {
        self.flags & ph_flags::PF_X != 0
    }

    pub fn has_wx(&self) -> bool {
        self.is_writable() && self.is_executable()
    }

    pub fn bss_size(&self) -> u64 {
        if self.mem_size > self.file_size {
            self.mem_size - self.file_size
        } else {
            0
        }
    }

    pub fn end_addr(&self) -> u64 {
        self.target_addr + self.mem_size
    }

    pub fn end_file_offset(&self) -> u64 {
        self.file_offset + self.file_size
    }

    pub fn bss_start(&self) -> u64 {
        self.target_addr + self.file_size
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.target_addr && addr < self.end_addr()
    }

    pub fn overlaps(&self, other: &LoadedSegment) -> bool {
        self.target_addr < other.end_addr() && other.target_addr < self.end_addr()
    }
}

impl Default for LoadedSegment {
    fn default() -> Self {
        Self {
            file_offset: 0,
            file_size: 0,
            mem_size: 0,
            target_addr: 0,
            alignment: 0x1000,
            flags: 0,
        }
    }
}
