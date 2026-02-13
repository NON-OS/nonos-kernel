// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::log::logger::{log_info, log_warn};
use core::convert::TryInto;

use super::keys::{
    derive_keyid, init_production_keys, is_initialized, KeyId, KeyStatus, KEYSTORE,
    NONOS_SIGNING_KEY,
};

pub const SIG_LEN: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Bounds,
    MalformedSignature,
    InvalidSignature,
    KeyNotFound,
    NotInitialized,
    KeyRevoked,
    KeyVersionTooOld,
}

#[derive(Debug, Clone)]
pub struct CapsuleMetadata {
    pub offset_sig: usize,
    pub len_sig: usize,
    pub offset_payload: usize,
    pub len_payload: usize,
    pub signer_keyid: Option<KeyId>,
    pub payload_hash: [u8; 32],
    pub header_version: u32,
    pub header_timestamp: u64,
}

impl Default for CapsuleMetadata {
    fn default() -> Self {
        Self {
            offset_sig: 0,
            len_sig: 0,
            offset_payload: 0,
            len_payload: 0,
            signer_keyid: None,
            payload_hash: [0u8; 32],
            header_version: 0,
            header_timestamp: 0,
        }
    }
}

pub fn verify_signature_bytes(data: &[u8], sig_bytes: &[u8]) -> Result<KeyId, VerifyError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if sig_bytes.len() != SIG_LEN {
        return Err(VerifyError::MalformedSignature);
    }

    if !is_initialized() {
        return Err(VerifyError::NotInitialized);
    }

    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| VerifyError::MalformedSignature)?;
    let sig = Signature::from_bytes(&sig_arr);

    let store = KEYSTORE.lock();
    for i in 0..store.count {
        let pk_bytes = &store.keys[i];
        let version = store.versions[i];

        if let Ok(pk) = VerifyingKey::from_bytes(pk_bytes) {
            if pk.verify(data, &sig).is_ok() {
                let key_id = derive_keyid(pk_bytes);

                match store.validate_key(pk_bytes, version) {
                    KeyStatus::Valid => return Ok(key_id),
                    KeyStatus::Revoked => return Err(VerifyError::KeyRevoked),
                    KeyStatus::VersionTooOld => return Err(VerifyError::KeyVersionTooOld),
                    KeyStatus::Expired => return Err(VerifyError::KeyRevoked),
                    KeyStatus::Unknown => return Err(VerifyError::KeyNotFound),
                }
            }
        }
    }

    Err(VerifyError::InvalidSignature)
}

pub fn verify_signature_full(blob: &[u8], meta: &CapsuleMetadata) -> Result<KeyId, VerifyError> {
    let sig_start = meta.offset_sig;
    let sig_end = sig_start
        .checked_add(meta.len_sig)
        .ok_or(VerifyError::Bounds)?;
    let pay_start = meta.offset_payload;
    let pay_end = pay_start
        .checked_add(meta.len_payload)
        .ok_or(VerifyError::Bounds)?;

    if sig_end > blob.len() || pay_end > blob.len() {
        return Err(VerifyError::Bounds);
    }

    let signature_bytes = &blob[sig_start..sig_end];
    let payload_bytes = &blob[pay_start..pay_end];

    if signature_bytes.len() != SIG_LEN {
        return Err(VerifyError::MalformedSignature);
    }

    // SAFETY: reject unsigned binaries
    if signature_bytes.iter().all(|&b| b == 0) {
        return Err(VerifyError::MalformedSignature);
    }

    verify_signature_bytes(payload_bytes, signature_bytes)
}

pub fn verify_signature(blob: &[u8], meta: &CapsuleMetadata) -> bool {
    match verify_signature_full(blob, meta) {
        Ok(_) => {
            log_info("crypto", "signature verified");
            true
        }
        Err(_) => {
            log_warn("crypto", "signature verification failed");
            false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    NotSigned,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateStatus {
    Trusted,
    Untrusted,
    Revoked,
    Expired,
    NotFound,
}

pub struct SignatureVerifier {
    initialized: bool,
}

impl SignatureVerifier {
    pub const fn new() -> Self {
        Self { initialized: false }
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        if self.initialized {
            return Ok(());
        }
        init_production_keys()?;
        self.initialized = true;
        Ok(())
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> SignatureStatus {
        if !self.initialized {
            return SignatureStatus::Error;
        }
        match verify_signature_bytes(data, signature) {
            Ok(_) => SignatureStatus::Valid,
            Err(VerifyError::InvalidSignature) => SignatureStatus::Invalid,
            Err(_) => SignatureStatus::Error,
        }
    }
}

pub fn perform_crypto_self_test() -> bool {
    let blake3_ok = {
        let test = b"NONOS-crypto-selftest";
        let h1 = blake3::hash(test);
        let h2 = blake3::hash(test);
        h1.as_bytes() == h2.as_bytes()
    };

    let ed25519_ok = {
        use ed25519_dalek::VerifyingKey;
        VerifyingKey::from_bytes(NONOS_SIGNING_KEY).is_ok()
    };

    blake3_ok && ed25519_ok
}
