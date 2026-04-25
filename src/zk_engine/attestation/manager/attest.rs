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

use super::super::types::KernelAttestation;
use super::types::AttestationManager;
use crate::zk_engine::ZKError;
use alloc::vec;

impl AttestationManager {
    pub fn generate_attestation(&mut self) -> Result<KernelAttestation, ZKError> {
        let measurement = super::measure::measure_kernel_state(self)?;
        self.measurement_history.push(measurement.clone());
        let signature = super::proof::sign_measurement(self, &measurement)?;
        let zk_proof = super::proof::generate_integrity_proof(self, &measurement)?;
        Ok(KernelAttestation {
            measurement,
            signature,
            zk_proof,
            public_key: self.signing_keypair.public,
            timestamp: crate::time::timestamp_millis(),
        })
    }

    pub fn verify_attestation(attestation: &KernelAttestation) -> Result<bool, ZKError> {
        let message = attestation.measurement.to_bytes();
        if !crate::crypto::ed25519::verify(
            &attestation.public_key,
            &message,
            &attestation.signature,
        ) {
            return Ok(false);
        }
        if let Some(ref proof) = attestation.zk_proof {
            if let Some(engine) = crate::zk_engine::get_zk_engine_static() {
                let zk_proof = crate::zk_engine::ZKProof {
                    circuit_id: proof.circuit_id,
                    proof_data: proof.clone(),
                    public_inputs: vec![],
                    proof_hash: [0; 32],
                    created_at: crate::time::timestamp_millis(),
                };
                return engine.verify_proof(&zk_proof);
            }
        }
        Ok(true)
    }
}
