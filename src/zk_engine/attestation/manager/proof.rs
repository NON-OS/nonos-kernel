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

use super::super::types::KernelMeasurement;
use super::types::AttestationManager;
use crate::crypto::ed25519::Signature as Ed25519Signature;
use crate::zk_engine::circuit::{Circuit, CircuitBuilder, LinearCombination};
use crate::zk_engine::groth16::Proof;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(super) fn sign_measurement(
    mgr: &AttestationManager,
    measurement: &KernelMeasurement,
) -> Result<Ed25519Signature, ZKError> {
    let message = measurement.to_bytes();
    Ok(crate::crypto::ed25519::sign(&mgr.signing_keypair, &message))
}

pub(super) fn generate_integrity_proof(
    mgr: &AttestationManager,
    measurement: &KernelMeasurement,
) -> Result<Option<Proof>, ZKError> {
    let Some(engine) = mgr.zk_engine else {
        return Ok(None);
    };
    let Some(ref _circuit) = mgr.attestation_circuit else {
        return Ok(None);
    };
    let witness = measurement.to_witness()?;
    let public_inputs = measurement.to_field_elements()?;
    let circuit_id = 1;
    let public_inputs_bytes: Vec<Vec<u8>> =
        public_inputs.iter().map(|fe| fe.to_bytes().to_vec()).collect();
    let zk_proof = engine.generate_proof(circuit_id, witness, public_inputs_bytes)?;
    Ok(Some(zk_proof.proof_data))
}

pub(super) fn build_attestation_circuit() -> Result<Circuit, ZKError> {
    let mut builder = CircuitBuilder::new();
    let integrity_hash_var = builder.alloc_input(Some("integrity_hash"));
    let code_hash_var = builder.alloc_variable(Some("code_hash"));
    let data_hash_var = builder.alloc_variable(Some("data_hash"));
    let config_hash_var = builder.alloc_variable(Some("config_hash"));
    let temp1 = builder.alloc_variable(Some("temp1"));
    let temp2 = builder.alloc_variable(Some("temp2"));
    builder.enforce_multiplication(code_hash_var, data_hash_var, temp1);
    builder.enforce_multiplication(temp1, config_hash_var, temp2);
    builder.enforce_equal(
        LinearCombination::from_variable(temp2),
        LinearCombination::from_variable(integrity_hash_var),
    );
    Ok(builder.build(4)?)
}
