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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};
use spin::RwLock;

use super::super::error::{FsError, FsResult};
use super::super::types::*;
use super::crypto::{encrypt_file_data, decrypt_file_data};
use super::key::FileKey;
use super::path::validate_path;

#[derive(Debug)]
pub struct NonosFilesystem {
    pub filesystem_type: NonosFileSystemType,
    pub files: RwLock<BTreeMap<String, NonosFile>>,
    pub file_keys: RwLock<BTreeMap<String, FileKey>>,
    pub encryption_enabled: bool,
    pub nonce_counter: AtomicU64,
    pub stats: RwLock<FsStatistics>,
}

impl NonosFilesystem {
    pub const fn new() -> Self {
        Self {
            filesystem_type: NonosFileSystemType::Ephemeral,
            files: RwLock::new(BTreeMap::new()),
            file_keys: RwLock::new(BTreeMap::new()),
            encryption_enabled: false,
            nonce_counter: AtomicU64::new(0),
            stats: RwLock::new(FsStatistics {
                files: 0,
                bytes_stored: 0,
                reads: 0,
                writes: 0,
                deletes: 0,
                encryptions: 0,
                decryptions: 0,
                decryption_failures: 0,
            }),
        }
    }

    pub fn new_encrypted() -> Self {
        Self {
            filesystem_type: NonosFileSystemType::Encrypted,
            files: RwLock::new(BTreeMap::new()),
            file_keys: RwLock::new(BTreeMap::new()),
            encryption_enabled: true,
            nonce_counter: AtomicU64::new(0),
            stats: RwLock::new(FsStatistics::default()),
        }
    }

    pub fn enable_encryption(&mut self) {
        self.encryption_enabled = true;
        self.filesystem_type = NonosFileSystemType::Encrypted;
    }

    fn get_timestamp(&self) -> u64 {
        crate::time::current_ticks()
    }

    fn ensure_key(&self, filename: &str) -> FsResult<[u8; KEY_SIZE]> {
        {
            let keys = self.file_keys.read();
            if let Some(file_key) = keys.get(filename) {
                return Ok(file_key.key);
            }
        }

        let mut keys = self.file_keys.write();

        if let Some(file_key) = keys.get(filename) {
            return Ok(file_key.key);
        }

        let file_key = FileKey::new(filename);
        let key = file_key.key;
        keys.insert(filename.to_string(), file_key);
        Ok(key)
    }

    fn get_key(&self, filename: &str) -> FsResult<[u8; KEY_SIZE]> {
        let keys = self.file_keys.read();
        let file_key = keys.get(filename).ok_or(FsError::NoEncryptionKey)?;
        Ok(file_key.key)
    }

    pub fn create_file(&self, name: &str, data: &[u8]) -> FsResult<()> {
        validate_path(name)?;

        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::FileTooLarge);
        }

        {
            let files = self.files.read();
            if files.len() >= MAX_FILES {
                return Err(FsError::TooManyFiles);
            }
        }

        let timestamp = self.get_timestamp();

        let stored = if self.encryption_enabled {
            let key = self.ensure_key(name)?;
            encrypt_file_data(data, &key, &self.nonce_counter, &self.stats)?
        } else {
            data.to_vec()
        };

        let file = NonosFile {
            name: name.to_string(),
            size: data.len(),
            data: stored,
            created: timestamp,
            modified: timestamp,
            encrypted: self.encryption_enabled,
            quantum_protected: matches!(self.filesystem_type, NonosFileSystemType::QuantumSafe),
        };

        self.files.write().insert(name.to_string(), file);

        {
            let mut stats = self.stats.write();
            stats.files += 1;
            stats.bytes_stored += data.len() as u64;
            stats.writes += 1;
        }

        Ok(())
    }

    pub fn read_file(&self, name: &str) -> FsResult<Vec<u8>> {
        validate_path(name)?;

        let files = self.files.read();
        let file = files.get(name).ok_or(FsError::NotFound)?;

        let result = if file.encrypted {
            let key = self.get_key(name)?;
            decrypt_file_data(&file.data, &key, &self.stats)?
        } else {
            file.data.clone()
        };

        {
            let mut stats = self.stats.write();
            stats.reads += 1;
        }

        Ok(result)
    }

    pub fn write_file(&self, name: &str, data: &[u8]) -> FsResult<()> {
        validate_path(name)?;

        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::FileTooLarge);
        }

        let mut files = self.files.write();
        let file = files.get_mut(name).ok_or(FsError::NotFound)?;

        secure_zeroize(&mut file.data);

        let stored = if self.encryption_enabled {
            let key = self.get_key(name)?;
            encrypt_file_data(data, &key, &self.nonce_counter, &self.stats)?
        } else {
            data.to_vec()
        };

        file.data = stored;
        file.size = data.len();
        file.modified = self.get_timestamp();

        {
            let mut stats = self.stats.write();
            stats.bytes_stored += data.len() as u64;
            stats.writes += 1;
        }

        Ok(())
    }

    pub fn delete_file(&self, name: &str) -> FsResult<()> {
        validate_path(name)?;

        {
            let mut files = self.files.write();
            if let Some(mut file) = files.remove(name) {
                file.secure_clear();
            } else {
                return Err(FsError::NotFound);
            }
        }

        {
            let mut keys = self.file_keys.write();
            if let Some(mut key) = keys.remove(name) {
                key.secure_clear();
            }
        }

        {
            let mut stats = self.stats.write();
            stats.files = stats.files.saturating_sub(1);
            stats.deletes += 1;
        }

        Ok(())
    }

    pub fn list_files(&self) -> Vec<String> {
        self.files.read().keys().cloned().collect()
    }

    pub fn get_file_info(&self, name: &str) -> FsResult<NonosFileInfo> {
        validate_path(name)?;

        let files = self.files.read();
        let file = files.get(name).ok_or(FsError::NotFound)?;

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
