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
use super::fs_helpers::{create_directory, create_file, create_symlink};
use super::types::{PackageArchive, ENTRY_DIR, ENTRY_FILE, ENTRY_SYMLINK};
use alloc::string::String;
use alloc::vec::Vec;

pub fn extract_package(archive: &PackageArchive, dest: &str) -> NpkgResult<Vec<String>> {
    let mut installed_files = Vec::new();
    for entry_result in archive.entries() {
        let entry = entry_result?;
        let full_path = if dest == "/" {
            entry.path.clone()
        } else {
            alloc::format!("{}{}", dest.trim_end_matches('/'), entry.path)
        };
        match entry.entry_type {
            ENTRY_DIR => {
                create_directory(&full_path, entry.mode)?;
            }
            ENTRY_FILE => {
                let data = archive.read_file(&entry)?;
                create_file(&full_path, &data, entry.mode)?;
            }
            ENTRY_SYMLINK => {
                if let Some(ref target) = entry.link_target {
                    create_symlink(&full_path, target)?;
                }
            }
            _ => {
                return Err(NpkgError::ExtractionFailed(alloc::format!(
                    "unknown entry type: {}",
                    entry.entry_type
                )));
            }
        }
        installed_files.push(full_path);
    }
    Ok(installed_files)
}
