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

pub(super) const NPKG_MAGIC: u32 = 0x4E504B47;
pub(super) const NPKG_VERSION: u32 = 1;
pub(super) const ENTRY_FILE: u8 = 0;
pub(super) const ENTRY_DIR: u8 = 1;
pub(super) const ENTRY_SYMLINK: u8 = 2;

pub struct PackageArchive<'a> {
    pub(super) data: &'a [u8],
    pub(crate) version: u32,
    pub(super) file_count: u32,
    pub(super) entries_offset: usize,
    pub(super) data_offset: usize,
}

#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub path: String,
    pub entry_type: u8,
    pub size: u64,
    pub mode: u32,
    pub checksum: [u8; 32],
    pub data_offset: u64,
    pub link_target: Option<String>,
}
