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

use alloc::string::String;
use alloc::vec::Vec;

pub use super::elf_constants::*;
pub use super::elf_structs::*;
pub use super::elf_loaded::*;
pub use super::elf_error::*;

#[derive(Debug, Clone)]
pub struct LoadedSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub flags: u32,
    pub file_offset: u64,
    pub filesz: u64,
}

impl LoadedSegment {
    pub fn end_addr(&self) -> u64 { self.vaddr.saturating_add(self.memsz) }
    pub fn is_readable(&self) -> bool { self.flags & PF_R != 0 }
    pub fn is_writable(&self) -> bool { self.flags & PF_W != 0 }
    pub fn is_executable(&self) -> bool { self.flags & PF_X != 0 }
    pub fn bss_size(&self) -> u64 { self.memsz.saturating_sub(self.filesz) }
    pub fn get_file_params(&self) -> (u64, u64) { (self.file_offset, self.filesz) }
}
