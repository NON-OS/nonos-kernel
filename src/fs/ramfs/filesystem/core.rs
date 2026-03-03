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

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::super::error::{FsError, FsResult};
use super::super::types::*;
use super::key::FileKey;

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

    pub(super) fn get_timestamp(&self) -> u64 {
        crate::time::current_ticks()
    }

    pub(super) fn ensure_key(&self, filename: &str) -> FsResult<[u8; KEY_SIZE]> {
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

    pub(super) fn get_key(&self, filename: &str) -> FsResult<[u8; KEY_SIZE]> {
        let keys = self.file_keys.read();
        let file_key = keys.get(filename).ok_or(FsError::NoEncryptionKey)?;
        Ok(file_key.key)
    }

    pub fn next_nonce(&self) -> u64 {
        self.nonce_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub fn current_nonce(&self) -> u64 {
        self.nonce_counter.load(Ordering::Relaxed)
    }
}
