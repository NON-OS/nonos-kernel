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

use core::sync::atomic::AtomicU64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionError {
    NotInitialized,
    InvalidRegion,
    KeyGenerationFailed,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailed,
    RegionNotFound,
    AlreadyProtected,
    SizeMismatch,
}

#[derive(Debug, Clone)]
pub struct EncryptedRegion {
    pub start: u64,
    pub size: usize,
    pub key_id: u64,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub encrypted: bool,
}

impl EncryptedRegion {
    pub fn new(start: u64, size: usize, key_id: u64) -> Self {
        Self { start, size, key_id, nonce: [0u8; 12], tag: [0u8; 16], encrypted: false }
    }
}

#[derive(Debug, Default)]
pub struct MemEncryptStats {
    pub regions_protected: AtomicU64,
    pub bytes_encrypted: AtomicU64,
    pub encryptions: AtomicU64,
    pub decryptions: AtomicU64,
    pub key_rotations: AtomicU64,
    pub auth_failures: AtomicU64,
}
