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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::error::{FsError, FsResult};
use super::super::types::FsStatistics;
use super::core::NonosFilesystem;

pub static NONOS_FILESYSTEM: NonosFilesystem = NonosFilesystem::new();

pub fn init_nonos_filesystem() -> FsResult<()> {
    init_nonos_fs()
}

pub fn get_filesystem() -> Option<&'static NonosFilesystem> {
    Some(&NONOS_FILESYSTEM)
}

pub fn create_file(name: &str, data: &[u8]) -> FsResult<()> {
    NONOS_FILESYSTEM.create_file(name, data)
}

pub fn read_file(name: &str) -> FsResult<Vec<u8>> {
    NONOS_FILESYSTEM.read_file(name)
}

pub fn write_file(name: &str, data: &[u8]) -> FsResult<()> {
    NONOS_FILESYSTEM.write_file(name, data)
}

/// # Safety
/// Atomic write-or-create. Prevents TOCTOU by combining exists check with write.
pub fn write_or_create(name: &str, data: &[u8]) -> FsResult<()> {
    NONOS_FILESYSTEM.write_or_create(name, data)
}

pub fn delete_file(name: &str) -> FsResult<()> {
    NONOS_FILESYSTEM.delete_file(name)
}

pub fn list_files() -> Vec<String> {
    NONOS_FILESYSTEM.list_files()
}

pub fn exists(name: &str) -> bool {
    NONOS_FILESYSTEM.exists(name)
}

pub fn file_exists(name: &str) -> bool {
    exists(name)
}

pub fn delete(path: &str) -> FsResult<()> {
    if exists(path) {
        return delete_file(path);
    }
    let normalized = path.trim_end_matches('/');
    let marker_path = format!("{}/.dir", normalized);
    if exists(&marker_path) {
        return delete_file(&marker_path);
    }
    Err(FsError::NotFound)
}

pub fn rename(old_path: &str, new_path: &str) -> FsResult<()> {
    NONOS_FILESYSTEM.atomic_rename(old_path, new_path)
}

pub fn stats() -> FsStatistics {
    NONOS_FILESYSTEM.stats()
}

pub fn init_nonos_fs() -> FsResult<()> {
    crate::log_info!("Initializing NONOS RAM-only filesystem");

    let _ = create_file("/ram/.dir", b"");
    let _ = create_file("/disk/.dir", b"");
    let _ = create_file("/disk/0/.dir", b"");
    let _ = create_file("/disk/1/.dir", b"");
    let _ = create_file("/home/.dir", b"");
    let _ = create_file("/tmp/.dir", b"");
    let _ = create_file("/capsules/.dir", b"");

    match create_file("zero_state_init", b"ZeroState FS initialized (RAM-only)") {
        Ok(_) => {
            crate::log_info!("NONOS filesystem initialization successful");
            Ok(())
        }
        Err(e) => {
            crate::log_err!("NONOS filesystem initialization failed: {}", e.as_str());
            Err(FsError::IoError("Failed to initialize filesystem"))
        }
    }
}
