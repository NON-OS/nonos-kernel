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

#[derive(Debug, Clone)]
pub struct PackageFile {
    pub path: String,
    pub size: u64,
    pub checksum: [u8; 32],
    pub permissions: FilePermissions,
    pub is_config: bool,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct FilePermissions {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Default for FilePermissions {
    fn default() -> Self {
        Self { mode: 0o644, uid: 0, gid: 0 }
    }
}

impl FilePermissions {
    pub fn executable() -> Self {
        Self { mode: 0o755, uid: 0, gid: 0 }
    }

    pub fn directory() -> Self {
        Self { mode: 0o755, uid: 0, gid: 0 }
    }
}
