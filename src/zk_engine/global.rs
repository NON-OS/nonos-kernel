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
use super::types::{ZKConfig, ZKProof, ZKError};
use super::engine::ZKEngine;
use super::circuit::Constraint;
use super::attestation::init_attestation_manager;

static ZK_ENGINE: spin::Once<ZKEngine> = spin::Once::new();

pub fn init_zk_engine() -> Result<(), ZKError> {
    let config = ZKConfig::default();
    let engine = ZKEngine::new(config)?;
    ZK_ENGINE.call_once(|| engine);
    init_attestation_manager()?;
    crate::log::info!("ZK Engine and attestation manager initialized successfully");
    Ok(())
}

/// Get the ZK engine, auto-initializing if needed.
/// Returns None if initialization fails.
fn try_get_or_init_zk_engine() -> Option<&'static ZKEngine> {
    // Try to get existing engine first (fast path)
    if let Some(engine) = ZK_ENGINE.get() {
        return Some(engine);
    }
    // Auto-initialize (slow path, only happens once)
    match init_zk_engine() {
        Ok(_) => ZK_ENGINE.get(),
        Err(e) => {
            crate::log::error!("ZK Engine auto-initialization failed: {:?}", e);
            None
        }
    }
}

/// Get the ZK engine, auto-initializing if needed.
/// Returns an error if not initialized and initialization fails.
pub fn get_zk_engine() -> Result<&'static ZKEngine, ZKError> {
    try_get_or_init_zk_engine().ok_or(ZKError::NotInitialized)
}

/// Try to get the ZK engine without auto-initialization.
pub fn get_zk_engine_static() -> Option<&'static ZKEngine> {
    ZK_ENGINE.get()
}

/// Check if the ZK engine has been initialized
pub fn is_zk_engine_initialized() -> bool {
    ZK_ENGINE.get().is_some()
}

pub fn compile_circuit(constraints: Vec<Constraint>, num_witnesses: usize) -> Result<u32, ZKError> {
    get_zk_engine()?.compile_circuit(constraints, num_witnesses)
}

pub fn generate_proof(circuit_id: u32, witness: Vec<Vec<u8>>, public_inputs: Vec<Vec<u8>>) -> Result<ZKProof, ZKError> {
    get_zk_engine()?.generate_proof(circuit_id, witness, public_inputs)
}

pub fn verify_proof(proof: &ZKProof) -> Result<bool, ZKError> {
    get_zk_engine()?.verify_proof(proof)
}

pub fn generate_groth16_proof(circuit_id: u32, witness: Vec<Vec<u8>>, public_inputs: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.generate_proof(circuit_id, witness, public_inputs) {
        Ok(proof) => Ok(engine.serialize_proof(&proof)),
        Err(_) => Err("Failed to generate Groth16 proof"),
    }
}

pub fn verify_groth16_proof(proof_data: &[u8]) -> Result<bool, &'static str> {
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.deserialize_proof(proof_data) {
        Ok(proof) => match engine.verify_proof(&proof) {
            Ok(valid) => Ok(valid),
            Err(_) => Err("Failed to verify Groth16 proof"),
        },
        Err(_) => Err("Invalid proof format"),
    }
}

pub fn generate_plonk_proof(circuit_id: u32, witness: Vec<Vec<u8>>, public_inputs: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.generate_proof(circuit_id, witness, public_inputs) {
        Ok(proof) => {
            let mut plonk_proof = vec![0x50, 0x4C, 0x4F, 0x4E];
            plonk_proof.extend(engine.serialize_proof(&proof));
            Ok(plonk_proof)
        },
        Err(_) => Err("Failed to generate PLONK proof"),
    }
}

pub fn verify_plonk_proof(proof_data: &[u8]) -> Result<bool, &'static str> {
    if proof_data.len() < 4 || &proof_data[0..4] != b"PLON" {
        return Err("Invalid PLONK proof format");
    }
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.deserialize_proof(&proof_data[4..]) {
        Ok(proof) => match engine.verify_proof(&proof) {
            Ok(valid) => Ok(valid),
            Err(_) => Err("Failed to verify PLONK proof"),
        },
        Err(_) => Err("Invalid PLONK proof format"),
    }
}

pub fn generate_stark_proof(circuit_id: u32, witness: Vec<Vec<u8>>, public_inputs: Vec<Vec<u8>>) -> Result<Vec<u8>, &'static str> {
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.generate_proof(circuit_id, witness, public_inputs) {
        Ok(proof) => {
            let mut stark_proof = vec![0x53, 0x54, 0x41, 0x52];
            stark_proof.extend(engine.serialize_proof(&proof));
            Ok(stark_proof)
        },
        Err(_) => Err("Failed to generate STARK proof"),
    }
}

pub fn verify_stark_proof(proof_data: &[u8]) -> Result<bool, &'static str> {
    if proof_data.len() < 4 || &proof_data[0..4] != b"STAR" {
        return Err("Invalid STARK proof format");
    }
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    match engine.deserialize_proof(&proof_data[4..]) {
        Ok(proof) => match engine.verify_proof(&proof) {
            Ok(valid) => Ok(valid),
            Err(_) => Err("Failed to verify STARK proof"),
        },
        Err(_) => Err("Invalid STARK proof format"),
    }
}
