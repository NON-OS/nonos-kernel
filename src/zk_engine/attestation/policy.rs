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

//! Attestation policy definitions.

use alloc::{vec::Vec, string::String};
use crate::zk_engine::ZKError;

use super::types::KernelAttestation;
use super::manager::AttestationManager;

/// Attestation policy for different security levels
#[derive(Debug, Clone)]
pub enum AttestationPolicy {
    /// Minimal verification - signature only
    SignatureOnly,
    /// Standard verification - signature + basic measurements
    Standard,
    /// High security - signature + measurements + ZK proofs
    HighSecurity,
    /// Custom policy with specific requirements
    Custom {
        require_zk_proof: bool,
        max_age_seconds: u64,
        required_modules: Vec<String>,
    },
}

impl AttestationPolicy {
    pub fn verify(&self, attestation: &KernelAttestation) -> Result<bool, ZKError> {
        match self {
            AttestationPolicy::SignatureOnly => {
                // Just verify signature
                let message = attestation.measurement.to_bytes();
                if attestation.public_key.len() != 32 {
                    return Err(ZKError::AttestationError("Invalid public key size".into()));
                }
                let mut pub_key_array = [0u8; 32];
                pub_key_array.copy_from_slice(&attestation.public_key);
                // Convert message to fixed size array for verification
                let message_hash = crate::crypto::hash::blake3_hash(&message);
                Ok(crate::crypto::ed25519::verify(&pub_key_array, &message_hash, &attestation.signature))
            }

            AttestationPolicy::Standard => {
                AttestationManager::verify_attestation(attestation)
            }

            AttestationPolicy::HighSecurity => {
                // Require ZK proof
                if attestation.zk_proof.is_none() {
                    return Ok(false);
                }

                AttestationManager::verify_attestation(attestation)
            }

            AttestationPolicy::Custom {
                require_zk_proof,
                max_age_seconds,
                required_modules
            } => {
                if *require_zk_proof && attestation.zk_proof.is_none() {
                    return Ok(false);
                }

                // Check age
                let current_time = crate::time::timestamp_millis();
                if current_time - attestation.timestamp > (*max_age_seconds * 1000) {
                    return Ok(false);
                }

                // Check required modules
                let module_names: Vec<String> = attestation.measurement.module_hashes
                    .iter()
                    .map(|m| m.name.clone())
                    .collect();

                for required in required_modules {
                    if !module_names.contains(required) {
                        return Ok(false);
                    }
                }

                AttestationManager::verify_attestation(attestation)
            }
        }
    }
}
