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
use alloc::string::String;

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
