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
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::keys::{derive_keyid, is_initialized, KeyId, KeyStatus, KEYSTORE};
use super::verify_types::{CapsuleMetadata, VerifyError, SIG_LEN};

pub fn verify_signature_bytes(data: &[u8], sig_bytes: &[u8]) -> Result<KeyId, VerifyError> {
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
