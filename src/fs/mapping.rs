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

use crate::memory::page_info::PageFlags;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingProtection {
    Read,
    ReadWrite,
    Execute,
    ReadExecute,
}

#[derive(Debug, Clone)]
pub struct FileMapping {
    pub file_id: u64,
    pub file_offset: u64,
    pub virtual_addr: x86_64::VirtAddr,
    pub size: usize,
    pub permissions: PageFlags,
}

impl FileMapping {
    pub fn new(
        file_id: u64,
        file_offset: u64,
        virtual_addr: x86_64::VirtAddr,
        size: usize,
        permissions: PageFlags,
    ) -> Self {
        Self {
            file_id,
            file_offset,
            virtual_addr,
            size,
            permissions,
        }
    }
}
