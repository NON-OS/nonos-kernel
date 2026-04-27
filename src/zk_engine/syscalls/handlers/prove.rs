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

use crate::process::core::ProcessControlBlock;
use crate::zk_engine::syscalls::helpers::*;
use crate::zk_engine::syscalls::params::*;
use crate::zk_engine::{get_zk_engine, ZKError};
use core::slice;

pub fn sys_zk_prove(
    params_ptr: usize,
    process: &ProcessControlBlock,
) -> Result<usize, &'static str> {
    if !is_valid_user_ptr(params_ptr, core::mem::size_of::<ZKProveParams>(), process) {
        return Err("Invalid parameters pointer");
    }
    let params = unsafe { &*(params_ptr as *const ZKProveParams) };
    if params.witness_len > MAX_WITNESS_SIZE {
        return Err("Witness size too large");
    }
    if params.public_inputs_len > MAX_PUBLIC_INPUTS * 32 {
        return Err("Public inputs too large");
    }
    if !is_valid_user_ptr(params.witness_ptr as usize, params.witness_len, process) {
        return Err("Invalid witness pointer");
    }
    if !is_valid_user_ptr(params.public_inputs_ptr as usize, params.public_inputs_len, process) {
        return Err("Invalid public inputs pointer");
    }
    if !is_valid_user_ptr(params.proof_output_ptr as usize, MAX_PROOF_SIZE, process) {
        return Err("Invalid proof output pointer");
    }
    let witness_data = unsafe { slice::from_raw_parts(params.witness_ptr, params.witness_len) };
    let public_inputs_data =
        unsafe { slice::from_raw_parts(params.public_inputs_ptr, params.public_inputs_len) };
    let witness = deserialize_witness(witness_data).map_err(|_| "Invalid witness format")?;
    let public_inputs = deserialize_public_inputs(public_inputs_data)
        .map_err(|_| "Invalid public inputs format")?;
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    let start_time = crate::time::timestamp_millis();
    let proof = match engine.generate_proof(params.circuit_id, witness, public_inputs) {
        Ok(proof) => proof,
        Err(ZKError::CircuitNotFound) => return Err("Circuit not found"),
        Err(ZKError::InvalidWitness) => return Err("Invalid witness"),
        Err(ZKError::ProvingFailed) => return Err("Proof generation failed"),
        Err(_) => return Err("ZK engine error"),
    };
    let proving_time = crate::time::timestamp_millis() - start_time;
    let proof_bytes = engine.serialize_proof(&proof);
    if proof_bytes.len() > MAX_PROOF_SIZE {
        return Err("Proof too large");
    }
    unsafe {
        let user_buffer = slice::from_raw_parts_mut(params.proof_output_ptr, proof_bytes.len());
        user_buffer.copy_from_slice(&proof_bytes);
        *(params.proof_output_len) = proof_bytes.len();
    }
    crate::log::info!(
        "Process {} generated ZK proof for circuit {} in {}ms",
        process.pid,
        params.circuit_id,
        proving_time
    );
    process.zk_proofs_generated.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    process.zk_proving_time_ms.fetch_add(proving_time, core::sync::atomic::Ordering::Relaxed);
    Ok(0)
}
