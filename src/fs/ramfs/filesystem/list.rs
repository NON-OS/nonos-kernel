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

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, compiler_fence};

use super::super::error::FsResult;
use super::super::types::*;
use super::core::NonosFilesystem;
use super::path::validate_path;

impl NonosFilesystem {
    pub fn list_files(&self) -> Vec<String> {
        self.files.read().keys().cloned().collect()
    }

    pub fn get_file_info(&self, name: &str) -> FsResult<NonosFileInfo> {
        validate_path(name)?;

        let files = self.files.read();
        let file = files.get(name).ok_or(super::super::error::FsError::NotFound)?;

        Ok(NonosFileInfo {
            name: file.name.clone(),
            size: file.size,
            created: file.created,
            modified: file.modified,
            encrypted: file.encrypted,
            quantum_protected: file.quantum_protected,
        })
    }

    pub fn exists(&self, name: &str) -> bool {
        self.files.read().contains_key(name)
    }

    pub fn stats(&self) -> FsStatistics {
        self.stats.read().clone()
    }

    pub fn file_count(&self) -> usize {
        self.files.read().len()
    }

    pub fn storage_used(&self) -> usize {
        self.files.read().values().map(|f| f.data.len()).sum()
    }

    pub fn clear_all(&self) {
        {
            let mut files = self.files.write();
            for (_, file) in files.iter_mut() {
                secure_zeroize(&mut file.data);
            }
            files.clear();
        }

        {
            let mut keys = self.file_keys.write();
            for (_, key) in keys.iter_mut() {
                key.secure_clear();
            }
            keys.clear();
        }

        {
            let mut stats = self.stats.write();
            *stats = FsStatistics::default();
        }

        self.nonce_counter.store(0, Ordering::SeqCst);

        compiler_fence(Ordering::SeqCst);
    }

    pub fn list_dir(&self, path: &str) -> FsResult<Vec<String>> {
        let entries = self.list_dir_entries(path)?;
        Ok(entries.into_iter().map(|e| {
            if e.is_dir {
                format!("{}/", e.name)
            } else {
                e.name
            }
        }).collect())
    }

    pub fn list_dir_entries(&self, path: &str) -> FsResult<Vec<DirEntry>> {
        let path_components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let files = self.files.read();

        let mut entries = Vec::new();
        let mut dirs: BTreeSet<String> = BTreeSet::new();

        for (filename, file) in files.iter() {
            let file_components: Vec<&str> = filename.split('/').filter(|s| !s.is_empty()).collect();

            if file_components.len() == path_components.len() + 1 {
                let mut matches = true;
                for (i, component) in path_components.iter().enumerate() {
                    if i >= file_components.len() || file_components[i] != *component {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    if let Some(last) = file_components.last() {
                        if *last != ".dir" {
                            entries.push(DirEntry {
                                name: (*last).to_string(),
                                is_dir: false,
                                size: file.size,
                            });
                        }
                    }
                }
            }

            if file_components.len() > path_components.len() + 1 {
                let mut matches = true;
                for (i, component) in path_components.iter().enumerate() {
                    if i >= file_components.len() || file_components[i] != *component {
                        matches = false;
                        break;
                    }
                }
                if matches && path_components.len() < file_components.len() {
                    dirs.insert(file_components[path_components.len()].to_string());
                }
            }
        }

        for dir in dirs {
            entries.push(DirEntry {
                name: dir,
                is_dir: true,
                size: 0,
            });
        }

        Ok(entries)
    }
}
