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

//! Extended key types for BIP-32.

extern crate alloc;

use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::crypto::asymmetric::secp256k1::{public_key_from_secret, CompressedPublicKey, SecretKey};
use crate::crypto::hash::{sha256, ripemd160};
use crate::crypto::{CryptoError, CryptoResult};

pub const HARDENED_OFFSET: u32 = 0x80000000;

#[derive(Clone)]
pub struct ExtendedPrivateKey {
    key: SecretKey,
    chain_code: [u8; 32],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_index: u32,
}

impl ExtendedPrivateKey {
    pub fn new(key: SecretKey, chain_code: [u8; 32]) -> Self {
        Self {
            key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_index: 0,
        }
    }

    pub fn with_metadata(
        key: SecretKey,
        chain_code: [u8; 32],
        depth: u8,
        parent_fingerprint: [u8; 4],
        child_index: u32,
    ) -> Self {
        Self {
            key,
            chain_code,
            depth,
            parent_fingerprint,
            child_index,
        }
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    pub fn child_index(&self) -> u32 {
        self.child_index
    }

    pub fn is_hardened(&self) -> bool {
        self.child_index >= HARDENED_OFFSET
    }

    pub fn public_key(&self) -> CryptoResult<ExtendedPublicKey> {
        let pk_bytes = public_key_from_secret(&self.key)
            .ok_or(CryptoError::InvalidKey)?;

        let compressed = compress_public_key(&pk_bytes)?;

        Ok(ExtendedPublicKey::with_metadata(
            compressed,
            self.chain_code,
            self.depth,
            self.parent_fingerprint,
            self.child_index,
        ))
    }

    pub fn fingerprint(&self) -> CryptoResult<[u8; 4]> {
        let pk = self.public_key()?;
        Ok(pk.fingerprint())
    }

    pub fn to_bytes(&self) -> [u8; 78] {
        let mut bytes = [0u8; 78];
        bytes[0..4].copy_from_slice(&[0x04, 0x88, 0xAD, 0xE4]);
        bytes[4] = self.depth;
        bytes[5..9].copy_from_slice(&self.parent_fingerprint);
        bytes[9..13].copy_from_slice(&self.child_index.to_be_bytes());
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45] = 0x00;
        bytes[46..78].copy_from_slice(&self.key);
        bytes
    }
}

impl Drop for ExtendedPrivateKey {
    fn drop(&mut self) {
        for byte in self.key.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        for byte in self.chain_code.iter_mut() {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct ExtendedPublicKey {
    key: CompressedPublicKey,
    chain_code: [u8; 32],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_index: u32,
}

impl ExtendedPublicKey {
    pub fn new(key: CompressedPublicKey, chain_code: [u8; 32]) -> Self {
        Self {
            key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_index: 0,
        }
    }

    pub fn with_metadata(
        key: CompressedPublicKey,
        chain_code: [u8; 32],
        depth: u8,
        parent_fingerprint: [u8; 4],
        child_index: u32,
    ) -> Self {
        Self {
            key,
            chain_code,
            depth,
            parent_fingerprint,
            child_index,
        }
    }

    pub fn public_key(&self) -> &CompressedPublicKey {
        &self.key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    pub fn child_index(&self) -> u32 {
        self.child_index
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        let hash = sha256(&self.key);
        let hash160 = ripemd160(&hash);
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&hash160[..4]);
        fp
    }

    pub fn to_bytes(&self) -> [u8; 78] {
        let mut bytes = [0u8; 78];
        bytes[0..4].copy_from_slice(&[0x04, 0x88, 0xB2, 0x1E]);
        bytes[4] = self.depth;
        bytes[5..9].copy_from_slice(&self.parent_fingerprint);
        bytes[9..13].copy_from_slice(&self.child_index.to_be_bytes());
        bytes[13..45].copy_from_slice(&self.chain_code);
        bytes[45..78].copy_from_slice(&self.key);
        bytes
    }
}

fn compress_public_key(uncompressed: &[u8; 65]) -> CryptoResult<CompressedPublicKey> {
    if uncompressed[0] != 0x04 {
        return Err(CryptoError::InvalidInput);
    }

    let mut compressed = [0u8; 33];
    let y_is_odd = (uncompressed[64] & 1) == 1;
    compressed[0] = if y_is_odd { 0x03 } else { 0x02 };
    compressed[1..33].copy_from_slice(&uncompressed[1..33]);

    Ok(compressed)
}
