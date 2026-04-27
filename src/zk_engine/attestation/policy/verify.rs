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

use super::custom::verify_custom;
use super::types::AttestationPolicy;
use crate::zk_engine::attestation::manager::AttestationManager;
use crate::zk_engine::attestation::types::KernelAttestation;
use crate::zk_engine::ZKError;

impl AttestationPolicy {
    pub fn verify(&self, attestation: &KernelAttestation) -> Result<bool, ZKError> {
        match self {
            AttestationPolicy::SignatureOnly => verify_signature_only(attestation),
            AttestationPolicy::Standard => AttestationManager::verify_attestation(attestation),
            AttestationPolicy::HighSecurity => {
                if attestation.zk_proof.is_none() {
                    return Ok(false);
                }
                AttestationManager::verify_attestation(attestation)
            }
            AttestationPolicy::Custom { require_zk_proof, max_age_seconds, required_modules } => {
                verify_custom(attestation, *require_zk_proof, *max_age_seconds, required_modules)
            }
        }
    }
}

fn verify_signature_only(attestation: &KernelAttestation) -> Result<bool, ZKError> {
    let message = attestation.measurement.to_bytes();
    if attestation.public_key.len() != 32 {
        return Err(ZKError::AttestationError("Invalid public key size".into()));
    }
    let mut pub_key_array = [0u8; 32];
    pub_key_array.copy_from_slice(&attestation.public_key);
    let message_hash = crate::crypto::hash::blake3_hash(&message);
    Ok(crate::crypto::ed25519::verify(&pub_key_array, &message_hash, &attestation.signature))
}
