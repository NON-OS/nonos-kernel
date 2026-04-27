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

use super::super::error::{NpkgError, NpkgResult};
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn create_directory(path: &str, mode: u32) -> NpkgResult<()> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();
    for component in components {
        current.push('/');
        current.push_str(component);
        if !directory_exists(&current) {
            crate::fs::mkdir(&current, mode).map_err(|_| {
                NpkgError::ExtractionFailed(alloc::format!("mkdir failed: {}", current))
            })?;
        }
    }
    Ok(())
}

pub(super) fn create_file(path: &str, data: &[u8], mode: u32) -> NpkgResult<()> {
    if let Some(parent) = parent_directory(path) {
        if !directory_exists(&parent) {
            create_directory(&parent, 0o755)?;
        }
    }
    crate::fs::nonos_vfs::vfs_write_file(path, data)
        .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("write failed: {}", path)))?;
    let _ = crate::fs::chmod(path, mode);
    Ok(())
}

pub(super) fn create_symlink(path: &str, target: &str) -> NpkgResult<()> {
    if let Some(parent) = parent_directory(path) {
        if !directory_exists(&parent) {
            create_directory(&parent, 0o755)?;
        }
    }
    crate::fs::symlink(target, path)
        .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("symlink failed: {}", path)))?;
    Ok(())
}

fn directory_exists(path: &str) -> bool {
    crate::fs::is_directory(path)
}

fn parent_directory(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');
    path.rfind('/').map(|idx| if idx == 0 { String::from("/") } else { String::from(&path[..idx]) })
}
