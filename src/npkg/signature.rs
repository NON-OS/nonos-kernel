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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use super::error::{NpkgError, NpkgResult};

pub const SIGNATURE_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SECRET_KEY_SIZE: usize = 64;

#[derive(Debug, Clone)]
pub struct PackageSignature {
    pub bytes: [u8; SIGNATURE_SIZE],
    pub key_id: [u8; 8],
    pub timestamp: u64,
}

impl PackageSignature {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < SIGNATURE_SIZE + 8 + 8 {
            return None;
        }

        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes.copy_from_slice(&data[..SIGNATURE_SIZE]);

        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&data[SIGNATURE_SIZE..SIGNATURE_SIZE + 8]);

        let timestamp = u64::from_le_bytes([
            data[SIGNATURE_SIZE + 8],
            data[SIGNATURE_SIZE + 9],
            data[SIGNATURE_SIZE + 10],
            data[SIGNATURE_SIZE + 11],
            data[SIGNATURE_SIZE + 12],
            data[SIGNATURE_SIZE + 13],
            data[SIGNATURE_SIZE + 14],
            data[SIGNATURE_SIZE + 15],
        ]);

        Some(Self {
            bytes,
            key_id,
            timestamp,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_SIZE + 8 + 8);
        out.extend_from_slice(&self.bytes);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out
    }
}

#[derive(Clone)]
pub struct SigningKey {
    secret: [u8; SECRET_KEY_SIZE],
    public: [u8; PUBLIC_KEY_SIZE],
}

impl SigningKey {
    pub fn from_bytes(secret: &[u8]) -> Option<Self> {
        if secret.len() != SECRET_KEY_SIZE {
            return None;
        }

        let mut secret_arr = [0u8; SECRET_KEY_SIZE];
        secret_arr.copy_from_slice(secret);

        let mut public = [0u8; 32];
        public.copy_from_slice(&secret_arr[32..64]);

        Some(Self {
            secret: secret_arr,
            public,
        })
    }

    pub fn public_key(&self) -> VerifyingKey {
        VerifyingKey { bytes: self.public }
    }

    pub fn key_id(&self) -> [u8; 8] {
        let hash = crate::crypto::blake3::blake3_hash(&self.public);
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[..8]);
        id
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        crate::crypto::zk_zeroize(&mut self.secret);
    }
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub bytes: [u8; PUBLIC_KEY_SIZE],
}

impl VerifyingKey {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != PUBLIC_KEY_SIZE {
            return None;
        }
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        bytes.copy_from_slice(data);
        Some(Self { bytes })
    }

    pub fn key_id(&self) -> [u8; 8] {
        let hash = crate::crypto::blake3::blake3_hash(&self.bytes);
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[..8]);
        id
    }
}

static TRUSTED_KEYS: Mutex<Vec<VerifyingKey>> = Mutex::new(Vec::new());
static KEYS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_trusted_keys() {
    if KEYS_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut keys = TRUSTED_KEYS.lock();

    if let Ok(key_data) = crate::fs::read_file_bytes("/etc/npkg/trusted.keys") {
        let mut offset = 0;
        while offset + PUBLIC_KEY_SIZE <= key_data.len() {
            if let Some(key) = VerifyingKey::from_bytes(&key_data[offset..offset + PUBLIC_KEY_SIZE]) {
                keys.push(key);
            }
            offset += PUBLIC_KEY_SIZE;
        }
    }

    if keys.is_empty() {
        if let Some(builtin) = get_builtin_key() {
            keys.push(builtin);
        }
    }
}

fn get_builtin_key() -> Option<VerifyingKey> {
    let key_path = "/boot/npkg_pubkey.bin";
    if let Ok(data) = crate::fs::read_file_bytes(key_path) {
        return VerifyingKey::from_bytes(&data);
    }

    if let Ok(data) = crate::fs::read_file_bytes("/etc/nonos/signing_pubkey.bin") {
        return VerifyingKey::from_bytes(&data);
    }

    None
}

pub fn add_trusted_key(key: VerifyingKey) {
    let mut keys = TRUSTED_KEYS.lock();
    let key_id = key.key_id();
    if !keys.iter().any(|k| k.key_id() == key_id) {
        keys.push(key);
    }
}

pub fn remove_trusted_key(key_id: &[u8; 8]) {
    let mut keys = TRUSTED_KEYS.lock();
    keys.retain(|k| &k.key_id() != key_id);
}

pub fn get_trusted_key(key_id: &[u8; 8]) -> Option<VerifyingKey> {
    let keys = TRUSTED_KEYS.lock();
    keys.iter().find(|k| &k.key_id() == key_id).cloned()
}

pub fn list_trusted_keys() -> Vec<VerifyingKey> {
    TRUSTED_KEYS.lock().clone()
}

pub fn generate_signing_keypair() -> (SigningKey, VerifyingKey) {
    let keypair = crate::crypto::ed25519::KeyPair::generate();

    let mut secret = [0u8; SECRET_KEY_SIZE];
    secret[..32].copy_from_slice(&keypair.private);
    secret[32..].copy_from_slice(&keypair.public);

    let signing = SigningKey {
        secret,
        public: keypair.public,
    };

    let verifying = VerifyingKey {
        bytes: keypair.public,
    };

    (signing, verifying)
}

pub fn sign_package(data: &[u8], key: &SigningKey) -> PackageSignature {
    let hash = crate::crypto::blake3::blake3_hash(data);

    let keypair = crate::crypto::ed25519::KeyPair {
        private: {
            let mut s = [0u8; 32];
            s.copy_from_slice(&key.secret[..32]);
            s
        },
        public: key.public,
    };

    let sig = crate::crypto::ed25519::sign(&keypair, &hash);

    PackageSignature {
        bytes: sig.to_bytes(),
        key_id: key.key_id(),
        timestamp: crate::time::unix_timestamp(),
    }
}

pub fn verify_package(data: &[u8], signature: &PackageSignature) -> NpkgResult<()> {
    init_trusted_keys();

    let key = get_trusted_key(&signature.key_id)
        .ok_or(NpkgError::SignatureKeyNotFound)?;

    let hash = crate::crypto::blake3::blake3_hash(data);

    let sig = crate::crypto::ed25519::Signature::from_bytes(&signature.bytes);

    if crate::crypto::ed25519::verify(&key.bytes, &hash, &sig) {
        Ok(())
    } else {
        Err(NpkgError::SignatureInvalid(alloc::format!(
            "key_id {:02x}{:02x}{:02x}{:02x}",
            signature.key_id[0],
            signature.key_id[1],
            signature.key_id[2],
            signature.key_id[3]
        )))
    }
}

pub fn verify_package_with_key(data: &[u8], signature: &PackageSignature, key: &VerifyingKey) -> bool {
    let hash = crate::crypto::blake3::blake3_hash(data);
    let sig = crate::crypto::ed25519::Signature::from_bytes(&signature.bytes);
    crate::crypto::ed25519::verify(&key.bytes, &hash, &sig)
}

pub fn compute_checksum(data: &[u8]) -> [u8; 32] {
    crate::crypto::blake3::blake3_hash(data)
}

pub fn verify_checksum(data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = compute_checksum(data);
    constant_time_eq(&actual, expected)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
