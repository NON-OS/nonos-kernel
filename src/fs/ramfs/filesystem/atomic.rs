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
use core::sync::atomic::Ordering;

use super::super::error::{FsError, FsResult};
use super::core::NonosFilesystem;
use super::path::validate_path;

impl NonosFilesystem {
    pub fn atomic_rename(&self, old_name: &str, new_name: &str) -> FsResult<()> {
        validate_path(old_name)?;
        validate_path(new_name)?;
        if old_name == new_name {
            return Ok(());
        }
        let mut files = self.files.write();
        let mut file = files.remove(old_name).ok_or(FsError::NotFound)?;
        if files.contains_key(new_name) {
            if let Some(mut existing) = files.remove(new_name) {
                existing.secure_clear();
            }
        }
        file.name = new_name.to_string();
        file.modified = self.get_timestamp();
        files.insert(new_name.to_string(), file);
        if self.encryption_enabled {
            let mut keys = self.file_keys.write();
            if let Some(key) = keys.remove(old_name) {
                keys.insert(new_name.to_string(), key);
            }
        }
        Ok(())
    }

    pub fn atomic_exchange(&self, path1: &str, path2: &str) -> FsResult<()> {
        validate_path(path1)?;
        validate_path(path2)?;
        if path1 == path2 {
            return Ok(());
        }
        let mut files = self.files.write();
        let file1 = files.remove(path1).ok_or(FsError::NotFound)?;
        let file2 = files.remove(path2).ok_or(FsError::NotFound)?;
        files.insert(path1.to_string(), file2);
        files.insert(path2.to_string(), file1);
        if self.encryption_enabled {
            let mut keys = self.file_keys.write();
            if let (Some(k1), Some(k2)) = (keys.remove(path1), keys.remove(path2)) {
                keys.insert(path1.to_string(), k2);
                keys.insert(path2.to_string(), k1);
            }
        }
        Ok(())
    }

    pub fn atomic_link(&self, src: &str, dst: &str) -> FsResult<()> {
        validate_path(src)?;
        validate_path(dst)?;
        let files = self.files.read();
        let src_file = files.get(src).ok_or(FsError::NotFound)?;
        if files.contains_key(dst) {
            return Err(FsError::AlreadyExists);
        }
        let mut new_file = src_file.clone();
        new_file.name = dst.to_string();
        drop(files);
        let mut files = self.files.write();
        if files.contains_key(dst) {
            return Err(FsError::AlreadyExists);
        }
        files.insert(dst.to_string(), new_file);
        let mut stats = self.stats.write();
        stats.files += 1;
        Ok(())
    }

    pub fn atomic_compare_and_write(
        &self,
        name: &str,
        old_data: &[u8],
        new_data: &[u8],
    ) -> FsResult<bool> {
        validate_path(name)?;
        let mut files = self.files.write();
        let file = files.get_mut(name).ok_or(FsError::NotFound)?;
        let current = if file.encrypted {
            let key = self.get_key(name)?;
            super::crypto::decrypt_file_data(&file.data, &key, &self.stats)?
        } else {
            file.data.clone()
        };
        if current != old_data {
            return Ok(false);
        }
        let stored = if self.encryption_enabled {
            let key = self.get_key(name)?;
            super::crypto::encrypt_file_data(new_data, &key, &self.nonce_counter, &self.stats)?
        } else {
            new_data.to_vec()
        };
        let old_size = file.size;
        super::super::types::secure_zeroize(&mut file.data);
        file.data = stored;
        file.size = new_data.len();
        file.modified = self.get_timestamp();
        let mut stats = self.stats.write();
        stats.bytes_stored = stats.bytes_stored.saturating_sub(old_size as u64);
        stats.bytes_stored = stats.bytes_stored.saturating_add(new_data.len() as u64);
        stats.writes += 1;
        Ok(true)
    }

    pub fn transaction_id(&self) -> u64 {
        self.nonce_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub fn atomic_truncate(&self, name: &str, length: usize) -> FsResult<()> {
        validate_path(name)?;
        let mut files = self.files.write();
        let file = files.get_mut(name).ok_or(FsError::NotFound)?;
        let old_size = file.size;
        let current = if file.encrypted {
            let key = self.get_key(name)?;
            super::crypto::decrypt_file_data(&file.data, &key, &self.stats)?
        } else {
            file.data.clone()
        };
        let mut new_data = current;
        if length < new_data.len() {
            new_data.truncate(length);
        } else if length > new_data.len() {
            new_data.resize(length, 0);
        }
        let stored = if self.encryption_enabled {
            let key = self.get_key(name)?;
            super::crypto::encrypt_file_data(&new_data, &key, &self.nonce_counter, &self.stats)?
        } else {
            new_data
        };
        super::super::types::secure_zeroize(&mut file.data);
        file.data = stored;
        file.size = length;
        file.modified = self.get_timestamp();
        let mut stats = self.stats.write();
        stats.bytes_stored = stats.bytes_stored.saturating_sub(old_size as u64);
        stats.bytes_stored = stats.bytes_stored.saturating_add(length as u64);
        stats.writes += 1;
        Ok(())
    }
}
