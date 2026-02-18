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

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, compiler_fence};

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const SALT_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const MAX_ENCRYPTED_FILE_SIZE: usize = 64 * 1024 * 1024;
pub const MAX_PATH_LEN: usize = 4096;
pub const KEY_DERIVATION_CONTEXT: &[u8] = b"NONOS_CRYPTOFS_KEY_V1";
pub const FILE_AAD: &[u8] = b"NONOS_CRYPTOFS_FILE";

#[derive(Debug, Default, Clone)]
pub struct CryptoFsStatistics {
    pub files: u64,
    pub bytes_stored: u64,
    pub encryptions: u64,
    pub decryptions: u64,
    pub decryption_failures: u64,
    pub secure_deletes: u64,
    pub nonce_counter: u64,
}

#[inline]
pub fn secure_zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
pub fn secure_zeroize_array<const N: usize>(data: &mut [u8; N]) {
    secure_zeroize(data.as_mut_slice());
}

#[derive(Debug)]
pub struct FileEntry {
    pub inode: u64,
    pub key: [u8; KEY_SIZE],
    pub salt: [u8; SALT_SIZE],
    pub encrypted: Vec<u8>,
    pub created_at: u64,
    pub modified_at: u64,
}

impl FileEntry {
    pub fn secure_clear(&mut self) {
        secure_zeroize(&mut self.encrypted);
        secure_zeroize_array(&mut self.key);
        secure_zeroize_array(&mut self.salt);
        self.encrypted.clear();
    }

    pub fn plaintext_size(&self) -> usize {
        if self.encrypted.len() < NONCE_SIZE + TAG_SIZE {
            0
        } else {
            self.encrypted.len() - NONCE_SIZE - TAG_SIZE
        }
    }
}

impl Clone for FileEntry {
    fn clone(&self) -> Self {
        Self {
            inode: self.inode,
            key: self.key,
            salt: self.salt,
            encrypted: self.encrypted.clone(),
            created_at: self.created_at,
            modified_at: self.modified_at,
        }
    }
}

impl Drop for FileEntry {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub inode: u64,
    pub size: usize,
    pub encrypted_size: usize,
    pub created: u64,
    pub modified: u64,
}
