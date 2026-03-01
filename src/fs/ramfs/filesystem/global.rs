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
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Once;

use super::super::error::{FsError, FsResult};
use super::super::types::{DirEntry, FsStatistics};
use super::core::NonosFilesystem;

pub static NONOS_FILESYSTEM: NonosFilesystem = NonosFilesystem::new();

static GLOBAL_FS: Once<NonosFilesystem> = Once::new();

pub fn init_nonos_filesystem() -> FsResult<()> {
    GLOBAL_FS.call_once(|| NonosFilesystem::new());
    Ok(())
}

pub fn get_filesystem() -> Option<&'static NonosFilesystem> {
    GLOBAL_FS.get()
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

pub fn dir_exists(path: &str) -> bool {
    let dir_path = if path.ends_with('/') { path.to_string() } else { format!("{}/", path) };
    NONOS_FILESYSTEM.list_files().iter().any(|k| k.starts_with(&dir_path))
}

pub fn list_dir(path: &str) -> FsResult<Vec<String>> {
    let entries = if let Some(fs) = GLOBAL_FS.get() {
        fs.list_dir_entries(path)?
    } else {
        NONOS_FILESYSTEM.list_dir_entries(path)?
    };
    Ok(entries.into_iter().map(|e| {
        if e.is_dir {
            format!("{}/", e.name)
        } else {
            e.name
        }
    }).collect())
}

pub fn list_dir_entries(path: &str) -> FsResult<Vec<DirEntry>> {
    if let Some(fs) = GLOBAL_FS.get() {
        fs.list_dir_entries(path)
    } else {
        NONOS_FILESYSTEM.list_dir_entries(path)
    }
}

pub fn create_dir(path: &str) -> FsResult<()> {
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        return Ok(());
    }

    if let Some(parent_end) = normalized.rfind('/') {
        if parent_end > 0 {
            let parent = &normalized[..parent_end];
            let parent_marker = format!("{}/.dir", parent);
            if !exists(&parent_marker) {
                return Err(FsError::NotFound);
            }
        }
    }

    let marker_path = format!("{}/.dir", normalized);
    if exists(&marker_path) {
        return Err(FsError::AlreadyExists);
    }

    create_file(&marker_path, b"")
}

pub fn mkdir_all(path: &str) -> FsResult<()> {
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        return Ok(());
    }

    let components: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    let mut current_path = String::new();

    for component in components {
        if current_path.is_empty() {
            current_path = format!("/{}", component);
        } else {
            current_path = format!("{}/{}", current_path, component);
        }

        let marker_path = format!("{}/.dir", current_path);

        if !exists(&marker_path) {
            create_file(&marker_path, b"")?;
        }
    }

    Ok(())
}

pub fn delete(path: &str) -> FsResult<()> {
    if exists(path) {
        return delete_file(path);
    }
    let marker_path = if path.ends_with('/') {
        format!("{}.dir", path)
    } else {
        format!("{}/.dir", path)
    };
    if exists(&marker_path) {
        return delete_file(&marker_path);
    }
    Err(FsError::NotFound)
}

pub fn rename(old_path: &str, new_path: &str) -> FsResult<()> {
    let data = read_file(old_path)?;
    create_file(new_path, &data)?;
    delete_file(old_path)?;
    Ok(())
}

pub fn stats() -> FsStatistics {
    NONOS_FILESYSTEM.stats()
}

pub fn init_nonos_fs() -> FsResult<()> {
    crate::log_info!("Initializing NONOS RAM-only filesystem");

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
