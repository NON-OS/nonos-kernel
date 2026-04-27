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

use alloc::string::ToString;
use alloc::vec::Vec;

use super::super::error::{FsError, FsResult};
use super::super::types::*;
use super::core::NonosFilesystem;
use super::crypto::{decrypt_file_data, encrypt_file_data};
use super::path::validate_path;

impl NonosFilesystem {
    /// # Safety
    /// Creates a new file with given data. Validates path, size limits,
    /// and max file count before creation.
    pub fn create_file(&self, name: &str, data: &[u8]) -> FsResult<()> {
        validate_path(name)?;

        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::FileTooLarge);
        }

        {
            let files = self.files.read();
            if files.contains_key(name) {
                return Err(FsError::AlreadyExists);
            }
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
            mode: 0o644,
            uid: 0,
            gid: 0,
        };

        let was_new = self.files.write().insert(name.to_string(), file).is_none();

        if was_new {
            let mut stats = self.stats.write();
            stats.files += 1;
            stats.bytes_stored += data.len() as u64;
            stats.writes += 1;
        }

        Ok(())
    }

    /// # Safety
    /// Reads file data, decrypting if necessary. Validates path before access.
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

    /// # Safety
    /// Deletes file and securely clears its data and encryption key.
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
}
