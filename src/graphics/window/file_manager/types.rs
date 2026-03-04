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

use super::constants::MAX_NAME_LEN;

#[derive(Clone)]
pub struct FileEntry {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    pub is_dir: bool,
    pub size: u32,
    pub cluster: u32,
}

impl Default for FileEntry {
    fn default() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            is_dir: false,
            size: 0,
            cluster: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileSource {
    Ramfs,
    Fat32(u8),
}

pub enum FmResult {
    Ok,
    NotFound,
    AlreadyExists,
    NoSpace,
    InvalidName,
    ReadOnly,
    IoError,
}
