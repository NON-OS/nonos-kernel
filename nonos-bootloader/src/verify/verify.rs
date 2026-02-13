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

use super::capsule::CapsuleStatus;
use crate::crypto::sig::{verify_signature_bytes, CapsuleMetadata, VerifyError};

pub fn validate_capsule(capsule: &[u8]) -> (CapsuleStatus, Option<CapsuleMetadata>) {
    let (status, meta) = crate::verify::capsule::validate_capsule(capsule);
    (status, meta)
}

pub fn verify_ed25519_signature(data: &[u8], signature: &[u8]) -> Result<bool, &'static str> {
    if signature.len() != 64 {
        return Err("Invalid signature length - expected 64 bytes");
    }

    match verify_signature_bytes(data, signature) {
        Ok(_key_id) => Ok(true),
        Err(VerifyError::InvalidSignature) => Ok(false),
        Err(VerifyError::NotInitialized) => Err("Keystore not initialized"),
        Err(VerifyError::MalformedSignature) => Err("Malformed signature"),
        Err(_) => Err("Verification error"),
    }
}
