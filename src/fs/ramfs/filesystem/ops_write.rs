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

use super::super::error::{FsError, FsResult};
use super::super::types::*;
use super::core::NonosFilesystem;
use super::crypto::encrypt_file_data;
use super::path::validate_path;

impl NonosFilesystem {
    /// # Safety
    /// Writes data to existing file. Validates path and size limits.
    pub fn write_file(&self, name: &str, data: &[u8]) -> FsResult<()> {
        validate_path(name)?;

        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::FileTooLarge);
        }

        let mut files = self.files.write();
        let file = files.get_mut(name).ok_or(FsError::NotFound)?;

        let old_size = file.size;
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
            stats.bytes_stored = stats.bytes_stored.saturating_sub(old_size as u64);
            stats.bytes_stored += data.len() as u64;
            stats.writes += 1;
        }

        Ok(())
    }

    /// # Safety
    /// Atomic write-or-create operation. Avoids TOCTOU by checking existence
    /// and performing write/create in a single locked operation.
    pub fn write_or_create(&self, name: &str, data: &[u8]) -> FsResult<()> {
        validate_path(name)?;

        if data.len() > MAX_FILE_SIZE {
            return Err(FsError::FileTooLarge);
        }

        let mut files = self.files.write();
        let mut old_size: u64 = 0;
        let mut is_new = false;

        if let Some(file) = files.get_mut(name) {
            old_size = file.size as u64;
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
        } else {
            if files.len() >= MAX_FILES {
                return Err(FsError::TooManyFiles);
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

            files.insert(name.to_string(), file);
            is_new = true;
        }

        {
            let mut stats = self.stats.write();
            if is_new {
                stats.files += 1;
            }
            stats.bytes_stored = stats.bytes_stored.saturating_sub(old_size);
            stats.bytes_stored += data.len() as u64;
            stats.writes += 1;
        }

        Ok(())
    }

    pub fn chmod(&self, path: &str, mode: u32) -> FsResult<()> {
        validate_path(path)?;
        let mut files = self.files.write();
        if let Some(file) = files.get_mut(path) {
            file.mode = mode & 0o7777;
            file.modified = crate::time::timestamp_millis();
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    pub fn chown(&self, path: &str, uid: u32, gid: u32) -> FsResult<()> {
        validate_path(path)?;
        let mut files = self.files.write();
        if let Some(file) = files.get_mut(path) {
            file.uid = uid;
            file.gid = gid;
            file.modified = crate::time::timestamp_millis();
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }
}
