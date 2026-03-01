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

use alloc::{string::ToString, vec::Vec};
use core::sync::atomic::{Ordering, compiler_fence};

use crate::crypto::rng::fill_random_bytes;

use super::core::{CRYPTOFS, require_cryptofs};
use super::crypto::{derive_key, encrypt_data, decrypt_data, validate_path};
use super::error::{CryptoFsError, CryptoResult};
use super::types::*;

pub fn create_encrypted_file(_parent_inode: u64, path: &str, _caps: &[u8]) -> CryptoResult<u64> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    let mut inner = fs.inner.write();

    if let Some(entry) = inner.files.get(path) {
        return Ok(entry.inode);
    }

    let inode = inner.next_inode.fetch_add(1, Ordering::Relaxed);

    let mut salt = [0u8; SALT_SIZE];
    fill_random_bytes(&mut salt);
    let key = derive_key(path, &salt);
    let now = crate::time::current_ticks();

    let entry = FileEntry {
        inode,
        key,
        salt,
        encrypted: Vec::new(),
        created_at: now,
        modified_at: now,
    };

    inner.files.insert(path.to_string(), entry);

    drop(inner);
    let mut stats = fs.stats.write();
    stats.files += 1;

    Ok(inode)
}

pub fn create_ephemeral_file(path: &str, data: &[u8]) -> CryptoResult<u64> {
    validate_path(path)?;

    if data.len() > MAX_ENCRYPTED_FILE_SIZE {
        return Err(CryptoFsError::FileTooLarge);
    }

    let fs = require_cryptofs()?;
    let nonce = fs.next_nonce()?;

    let mut inner = fs.inner.write();

    let inode = inner.next_inode.fetch_add(1, Ordering::Relaxed);

    let mut salt = [0u8; SALT_SIZE];
    fill_random_bytes(&mut salt);
    let key = derive_key(path, &salt);
    let now = crate::time::current_ticks();

    let encrypted = encrypt_data(data, &key, &nonce)?;

    let entry = FileEntry {
        inode,
        key,
        salt,
        encrypted,
        created_at: now,
        modified_at: now,
    };

    inner.files.insert(path.to_string(), entry);

    drop(inner);
    let mut stats = fs.stats.write();
    stats.files += 1;
    stats.bytes_stored += data.len() as u64;
    stats.encryptions += 1;

    Ok(inode)
}

pub fn read_encrypted(path: &str) -> CryptoResult<Vec<u8>> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    let inner = fs.inner.read();
    let entry = inner.files.get(path).ok_or(CryptoFsError::NotFound)?;

    if entry.encrypted.is_empty() {
        return Ok(Vec::new());
    }

    let key = entry.key;
    let encrypted = entry.encrypted.clone();
    drop(inner);

    let result = decrypt_data(&encrypted, &key);

    let mut stats = fs.stats.write();
    if result.is_ok() {
        stats.decryptions += 1;
    } else {
        stats.decryption_failures += 1;
    }

    result
}

pub fn write_encrypted(path: &str, data: &[u8]) -> CryptoResult<()> {
    validate_path(path)?;

    if data.len() > MAX_ENCRYPTED_FILE_SIZE {
        return Err(CryptoFsError::FileTooLarge);
    }

    let fs = require_cryptofs()?;

    {
        let inner = fs.inner.read();
        if !inner.files.contains_key(path) {
            drop(inner);
            create_ephemeral_file(path, data)?;
            return Ok(());
        }
    }

    let nonce = fs.next_nonce()?;

    let mut inner = fs.inner.write();
    let entry = inner.files.get_mut(path).ok_or(CryptoFsError::NotFound)?;

    secure_zeroize(&mut entry.encrypted);

    entry.encrypted = encrypt_data(data, &entry.key, &nonce)?;
    entry.modified_at = crate::time::current_ticks();

    drop(inner);
    let mut stats = fs.stats.write();
    stats.bytes_stored += data.len() as u64;
    stats.encryptions += 1;

    Ok(())
}

pub fn delete_encrypted(path: &str) -> CryptoResult<()> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    let mut inner = fs.inner.write();

    if let Some(mut entry) = inner.files.remove(path) {
        entry.secure_clear();

        drop(inner);
        let mut stats = fs.stats.write();
        stats.files = stats.files.saturating_sub(1);
        stats.secure_deletes += 1;

        return Ok(());
    }

    Err(CryptoFsError::NotFound)
}

pub fn clear_crypto_state() {
    let fs = match CRYPTOFS.get() {
        Some(fs) => fs,
        None => return,
    };

    let mut inner = fs.inner.write();

    for (_, entry) in inner.files.iter_mut() {
        entry.secure_clear();
    }

    inner.files.clear();

    inner.nonce_counter.store(0, Ordering::SeqCst);

    drop(inner);
    let mut stats = fs.stats.write();
    *stats = CryptoFsStatistics::default();

    compiler_fence(Ordering::SeqCst);
}

pub fn rotate_file_key(path: &str) -> CryptoResult<()> {
    validate_path(path)?;
    let fs = require_cryptofs()?;

    let plaintext = read_encrypted(path)?;

    let nonce = fs.next_nonce()?;

    let mut inner = fs.inner.write();
    let entry = inner.files.get_mut(path).ok_or(CryptoFsError::NotFound)?;

    let mut new_salt = [0u8; SALT_SIZE];
    fill_random_bytes(&mut new_salt);
    let new_key = derive_key(path, &new_salt);

    secure_zeroize_array(&mut entry.key);
    secure_zeroize_array(&mut entry.salt);
    secure_zeroize(&mut entry.encrypted);

    entry.salt = new_salt;
    entry.key = new_key;

    entry.encrypted = encrypt_data(&plaintext, &entry.key, &nonce)?;
    entry.modified_at = crate::time::current_ticks();

    drop(inner);
    let mut stats = fs.stats.write();
    stats.encryptions += 1;

    Ok(())
}

pub fn nonce_counter_warning() -> bool {
    if let Some(fs) = CRYPTOFS.get() {
        let inner = fs.inner.read();
        let counter = inner.nonce_counter.load(Ordering::Relaxed);
        counter > (1u64 << 62)
    } else {
        false
    }
}
