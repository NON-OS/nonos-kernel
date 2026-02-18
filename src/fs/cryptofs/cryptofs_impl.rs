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

use alloc::{collections::BTreeMap, string::String, vec::Vec, string::ToString};
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};
use spin::{RwLock, Once};

use crate::crypto::chacha20poly1305::{aead_encrypt, aead_decrypt};
use crate::crypto::rng::fill_random_bytes;
use crate::crypto::hash::sha256;

use super::error::{CryptoFsError, CryptoResult};
use super::types::*;

struct CryptoInner {
    block_size: usize,
    total_blocks: usize,
    files: BTreeMap<String, FileEntry>,
    next_inode: AtomicU64,
    nonce_counter: AtomicU64,
}

impl core::fmt::Debug for CryptoInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoInner")
            .field("block_size", &self.block_size)
            .field("total_blocks", &self.total_blocks)
            .field("files_count", &self.files.len())
            .field("next_inode", &self.next_inode.load(Ordering::Relaxed))
            .field("nonce_counter", &self.nonce_counter.load(Ordering::Relaxed))
            .finish()
    }
}

fn derive_key(path: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
    let path_bytes = path.as_bytes();
    let total_len = SALT_SIZE + path_bytes.len() + KEY_DERIVATION_CONTEXT.len();

    let mut input = Vec::with_capacity(total_len);
    input.extend_from_slice(salt);
    input.extend_from_slice(path_bytes);
    input.extend_from_slice(KEY_DERIVATION_CONTEXT);

    sha256(&input)
}

fn generate_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    fill_random_bytes(&mut nonce[0..4]);
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn encrypt_data(data: &[u8], key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> CryptoResult<Vec<u8>> {
    let ct_and_tag = aead_encrypt(key, nonce, FILE_AAD, data)
        .map_err(|_| CryptoFsError::EncryptionFailed)?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ct_and_tag.len());
    result.extend_from_slice(nonce);
    result.extend_from_slice(&ct_and_tag);
    Ok(result)
}

fn decrypt_data(encrypted: &[u8], key: &[u8; KEY_SIZE]) -> CryptoResult<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoFsError::DataTooShort);
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&encrypted[0..NONCE_SIZE]);

    let ct_and_tag = &encrypted[NONCE_SIZE..];

    aead_decrypt(key, &nonce, FILE_AAD, ct_and_tag)
        .map_err(|_| CryptoFsError::AuthenticationFailed)
}

fn validate_path(path: &str) -> CryptoResult<()> {
    if path.is_empty() {
        return Err(CryptoFsError::InvalidPath);
    }
    if path.len() > MAX_PATH_LEN {
        return Err(CryptoFsError::PathTooLong);
    }
    if path.bytes().any(|b| b == 0) {
        return Err(CryptoFsError::InvalidPath);
    }
    Ok(())
}

#[derive(Debug)]
pub struct CryptoFileSystem {
    inner: RwLock<CryptoInner>,
    stats: RwLock<CryptoFsStatistics>,
}

impl CryptoFileSystem {
    fn new(total_blocks: usize, block_size: usize) -> Self {
        Self {
            inner: RwLock::new(CryptoInner {
                block_size,
                total_blocks,
                files: BTreeMap::new(),
                next_inode: AtomicU64::new(3),
                nonce_counter: AtomicU64::new(0),
            }),
            stats: RwLock::new(CryptoFsStatistics::default()),
        }
    }

    pub fn sync_all(&self) {
    }

    pub fn process_pending_operations(&self, _max_ops: usize) -> usize {
        0
    }

    pub fn stats(&self) -> CryptoFsStatistics {
        let stats = self.stats.read();
        let mut result = stats.clone();

        let inner = self.inner.read();
        result.nonce_counter = inner.nonce_counter.load(Ordering::Relaxed);
        result
    }

    pub fn exists(&self, path: &str) -> bool {
        let inner = self.inner.read();
        inner.files.contains_key(path)
    }

    pub fn get_file_info(&self, path: &str) -> CryptoResult<FileInfo> {
        let inner = self.inner.read();
        let entry = inner.files.get(path).ok_or(CryptoFsError::NotFound)?;

        Ok(FileInfo {
            inode: entry.inode,
            size: entry.plaintext_size(),
            encrypted_size: entry.encrypted.len(),
            created: entry.created_at,
            modified: entry.modified_at,
        })
    }

    pub fn list_files(&self) -> Vec<String> {
        let inner = self.inner.read();
        inner.files.keys().cloned().collect()
    }

    pub fn storage_used(&self) -> usize {
        let inner = self.inner.read();
        inner.files.values().map(|e| e.encrypted.len()).sum()
    }

    fn next_nonce(&self) -> CryptoResult<[u8; NONCE_SIZE]> {
        let inner = self.inner.read();
        let counter = inner.nonce_counter.fetch_add(1, Ordering::SeqCst);

        if counter == u64::MAX {
            return Err(CryptoFsError::NonceExhausted);
        }

        Ok(generate_nonce(counter))
    }
}

static CRYPTOFS: Once<CryptoFileSystem> = Once::new();

pub fn init_cryptofs(total_blocks: usize, block_size: usize) -> CryptoResult<()> {
    CRYPTOFS.call_once(|| CryptoFileSystem::new(total_blocks, block_size));
    Ok(())
}

pub fn get_cryptofs() -> Option<&'static CryptoFileSystem> {
    CRYPTOFS.get()
}

#[inline]
fn require_cryptofs() -> CryptoResult<&'static CryptoFileSystem> {
    CRYPTOFS.get().ok_or(CryptoFsError::NotInitialized)
}

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

pub fn create_encrypted_file_legacy(parent_inode: u64, path: &str, caps: &[u8]) -> Result<u64, &'static str> {
    create_encrypted_file(parent_inode, path, caps).map_err(|e| e.as_str())
}

pub fn create_ephemeral_file_legacy(path: &str, data: &[u8]) -> Result<u64, &'static str> {
    create_ephemeral_file(path, data).map_err(|e| e.as_str())
}

pub fn read_encrypted_legacy(path: &str) -> Result<Vec<u8>, &'static str> {
    read_encrypted(path).map_err(|e| e.as_str())
}

pub fn write_encrypted_legacy(path: &str, data: &[u8]) -> Result<(), &'static str> {
    write_encrypted(path, data).map_err(|e| e.as_str())
}

pub fn delete_encrypted_legacy(path: &str) -> Result<(), &'static str> {
    delete_encrypted(path).map_err(|e| e.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_error_to_errno() {
        assert_eq!(CryptoFsError::NotFound.to_errno(), -2);
        assert_eq!(CryptoFsError::AlreadyExists.to_errno(), -17);
        assert_eq!(CryptoFsError::PathTooLong.to_errno(), -36);
    }

    #[test]
    fn test_validate_path() {
        assert!(validate_path("/test/file").is_ok());
        assert!(validate_path("").is_err());
        assert!(validate_path(&"x".repeat(MAX_PATH_LEN + 1)).is_err());
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce(0);
        let nonce2 = generate_nonce(1);
        assert_ne!(nonce1[4..12], nonce2[4..12]);
    }

    #[test]
    fn test_secure_zeroize() {
        let mut data = [0xFFu8; 32];
        secure_zeroize(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
