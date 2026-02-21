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

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{Ordering, compiler_fence};

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;
pub const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_FILES: usize = 65536;
pub(super) const KEY_DERIVATION_CONTEXT: &[u8] = b"NONOS_FS_KEY_V1";
pub(super) const FILE_AAD: &[u8] = b"NONOS_FS_FILE";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosFileSystemType {
    QuantumSafe = 0,
    Encrypted = 1,
    Ephemeral = 2,
}

#[derive(Debug)]
pub struct NonosFile {
    pub name: String,
    pub data: Vec<u8>,
    pub size: usize,
    pub created: u64,
    pub modified: u64,
    pub encrypted: bool,
    pub quantum_protected: bool,
}

impl NonosFile {
    pub fn secure_clear(&mut self) {
        secure_zeroize(&mut self.data);
        self.data.clear();
        self.size = 0;
    }
}

impl Drop for NonosFile {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

#[derive(Debug, Clone)]
pub struct NonosFileInfo {
    pub name: String,
    pub size: usize,
    pub created: u64,
    pub modified: u64,
    pub encrypted: bool,
    pub quantum_protected: bool,
}

#[derive(Debug, Default, Clone)]
pub struct FsStatistics {
    pub files: u64,
    pub bytes_stored: u64,
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub encryptions: u64,
    pub decryptions: u64,
    pub decryption_failures: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: usize,
}
