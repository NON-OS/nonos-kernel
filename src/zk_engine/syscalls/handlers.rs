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

//! Syscall handler implementations.

use core::slice;
use crate::process::core::ProcessControlBlock;
use crate::zk_engine::{ZKError, get_zk_engine};
use super::params::*;
use super::helpers::*;

/// Main syscall dispatcher for ZK operations
pub fn handle_zk_syscall(
    syscall_num: usize,
    arg1: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
    process: &ProcessControlBlock,
) -> Result<usize, &'static str> {

    // Check if process has ZK permissions
    if !check_zk_permissions(process) {
        return Err("Process lacks ZK permissions");
    }

    match syscall_num {
        SYS_ZK_PROVE => sys_zk_prove(arg1, process),
        SYS_ZK_VERIFY => sys_zk_verify(arg1, process),
        SYS_ZK_COMPILE_CIRCUIT => sys_zk_compile_circuit(arg1, process),
        SYS_ZK_GET_STATS => sys_zk_get_stats(arg1, process),
        _ => Err("Invalid ZK syscall number"),
    }
}

/// sys_zk_prove: Generate a zero-knowledge proof
pub fn sys_zk_prove(params_ptr: usize, process: &ProcessControlBlock) -> Result<usize, &'static str> {
    // Validate parameters pointer
    if !is_valid_user_ptr(params_ptr, core::mem::size_of::<ZKProveParams>(), process) {
        return Err("Invalid parameters pointer");
    }

    // Read parameters from user space
    let params = unsafe {
        &*(params_ptr as *const ZKProveParams)
    };

    // Validate parameter values
    if params.witness_len > MAX_WITNESS_SIZE {
        return Err("Witness size too large");
    }

    if params.public_inputs_len > MAX_PUBLIC_INPUTS * 32 {
        return Err("Public inputs too large");
    }

    // Validate user pointers
    if !is_valid_user_ptr(params.witness_ptr as usize, params.witness_len, process) {
        return Err("Invalid witness pointer");
    }

    if !is_valid_user_ptr(params.public_inputs_ptr as usize, params.public_inputs_len, process) {
        return Err("Invalid public inputs pointer");
    }

    if !is_valid_user_ptr(params.proof_output_ptr as usize, MAX_PROOF_SIZE, process) {
        return Err("Invalid proof output pointer");
    }

    // Copy witness data from user space
    let witness_data = unsafe {
        slice::from_raw_parts(params.witness_ptr, params.witness_len)
    };

    // Copy public inputs from user space
    let public_inputs_data = unsafe {
        slice::from_raw_parts(params.public_inputs_ptr, params.public_inputs_len)
    };

    // Deserialize witness (simplified format: length-prefixed values)
    let witness = match deserialize_witness(witness_data) {
        Ok(w) => w,
        Err(_) => return Err("Invalid witness format"),
    };

    // Deserialize public inputs
    let public_inputs = match deserialize_public_inputs(public_inputs_data) {
        Ok(pi) => pi,
        Err(_) => return Err("Invalid public inputs format"),
    };

    // Generate proof using ZK engine
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

    // Serialize proof
    let proof_bytes = engine.serialize_proof(&proof);

    if proof_bytes.len() > MAX_PROOF_SIZE {
        return Err("Proof too large");
    }

    // Copy proof to user space
    unsafe {
        let user_buffer = slice::from_raw_parts_mut(params.proof_output_ptr, proof_bytes.len());
        user_buffer.copy_from_slice(&proof_bytes);

        // Update output length
        *(params.proof_output_len) = proof_bytes.len();
    }

    // Log the operation
    crate::log::info!(
        "Process {} generated ZK proof for circuit {} in {}ms",
        process.pid, params.circuit_id, proving_time
    );

    // Update process ZK usage statistics
    process.zk_proofs_generated.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    process.zk_proving_time_ms.fetch_add(proving_time, core::sync::atomic::Ordering::Relaxed);

    Ok(0) // Success
}

/// sys_zk_verify: Verify a zero-knowledge proof
pub fn sys_zk_verify(params_ptr: usize, process: &ProcessControlBlock) -> Result<usize, &'static str> {
    // Validate parameters pointer
    if !is_valid_user_ptr(params_ptr, core::mem::size_of::<ZKVerifyParams>(), process) {
        return Err("Invalid parameters pointer");
    }

    // Read parameters from user space
    let params = unsafe {
        &*(params_ptr as *const ZKVerifyParams)
    };

    // Validate parameter values
    if params.proof_len > MAX_PROOF_SIZE {
        return Err("Proof size too large");
    }

    // Validate user pointers
    if !is_valid_user_ptr(params.proof_ptr as usize, params.proof_len, process) {
        return Err("Invalid proof pointer");
    }

    if !is_valid_user_ptr(params.result_ptr as usize, core::mem::size_of::<bool>(), process) {
        return Err("Invalid result pointer");
    }

    // Copy proof data from user space
    let proof_data = unsafe {
        slice::from_raw_parts(params.proof_ptr, params.proof_len)
    };

    // Deserialize proof
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    let proof = match engine.deserialize_proof(proof_data) {
        Ok(proof) => proof,
        Err(_) => return Err("Invalid proof format"),
    };

    // Verify proof using ZK engine
    let start_time = crate::time::timestamp_millis();
    let is_valid = match engine.verify_proof(&proof) {
        Ok(result) => result,
        Err(ZKError::CircuitNotFound) => return Err("Circuit not found"),
        Err(ZKError::VerificationFailed) => return Err("Verification failed"),
        Err(_) => return Err("ZK engine error"),
    };

    let verification_time = crate::time::timestamp_millis() - start_time;

    // Copy result to user space
    unsafe {
        *(params.result_ptr) = is_valid;
    }

    // Log the operation
    crate::log::info!(
        "Process {} verified ZK proof for circuit {} in {}ms (result: {})",
        process.pid, proof.circuit_id, verification_time, is_valid
    );

    // Update process ZK usage statistics
    process.zk_proofs_verified.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    process.zk_verification_time_ms.fetch_add(verification_time, core::sync::atomic::Ordering::Relaxed);

    Ok(0) // Success
}

/// sys_zk_compile_circuit: Compile a circuit from constraints
pub fn sys_zk_compile_circuit(params_ptr: usize, process: &ProcessControlBlock) -> Result<usize, &'static str> {
    // Check if process has circuit compilation permissions
    if !check_circuit_compilation_permissions(process) {
        return Err("Process lacks circuit compilation permissions");
    }

    // Validate parameters pointer
    if !is_valid_user_ptr(params_ptr, core::mem::size_of::<ZKCompileParams>(), process) {
        return Err("Invalid parameters pointer");
    }

    // Read parameters from user space
    let params = unsafe {
        &*(params_ptr as *const ZKCompileParams)
    };

    // Validate parameter values
    if params.constraints_len > MAX_CONSTRAINTS * 64 { // Rough estimate
        return Err("Too many constraints");
    }

    if params.num_witnesses > MAX_WITNESS_SIZE / 32 {
        return Err("Too many witnesses");
    }

    // Validate user pointers
    if !is_valid_user_ptr(params.constraints_ptr as usize, params.constraints_len, process) {
        return Err("Invalid constraints pointer");
    }

    if !is_valid_user_ptr(params.circuit_id_ptr as usize, core::mem::size_of::<u32>(), process) {
        return Err("Invalid circuit ID output pointer");
    }

    // Copy constraints data from user space
    let constraints_data = unsafe {
        slice::from_raw_parts(params.constraints_ptr, params.constraints_len)
    };

    // Deserialize constraints
    let constraints = match deserialize_constraints(constraints_data) {
        Ok(c) => c,
        Err(_) => return Err("Invalid constraints format"),
    };

    // Compile circuit using ZK engine
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    let start_time = crate::time::timestamp_millis();
    let circuit_id = match engine.compile_circuit(constraints, params.num_witnesses) {
        Ok(id) => id,
        Err(ZKError::InvalidCircuit) => return Err("Invalid circuit"),
        Err(ZKError::OutOfMemory) => return Err("Out of memory"),
        Err(_) => return Err("Circuit compilation failed"),
    };

    let compilation_time = crate::time::timestamp_millis() - start_time;

    // Copy circuit ID to user space
    unsafe {
        *(params.circuit_id_ptr) = circuit_id;
    }

    // Log the operation
    crate::log::info!(
        "Process {} compiled circuit {} in {}ms",
        process.pid, circuit_id, compilation_time
    );

    // Update process ZK usage statistics
    process.zk_circuits_compiled.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    Ok(0) // Success
}

/// sys_zk_get_stats: Get ZK engine statistics
pub fn sys_zk_get_stats(stats_ptr: usize, process: &ProcessControlBlock) -> Result<usize, &'static str> {
    // Validate parameters pointer
    if !is_valid_user_ptr(stats_ptr, core::mem::size_of::<ZKStatsUserspace>(), process) {
        return Err("Invalid stats pointer");
    }

    // Get engine statistics
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    let engine_stats = engine.get_stats();

    let total_proofs = engine_stats.proofs_generated.load(core::sync::atomic::Ordering::SeqCst);
    let total_verifications = engine_stats.proofs_verified.load(core::sync::atomic::Ordering::SeqCst);
    let total_proving_time = engine_stats.total_proving_time_ms.load(core::sync::atomic::Ordering::SeqCst);
    let total_verification_time = engine_stats.total_verification_time_ms.load(core::sync::atomic::Ordering::SeqCst);

    let user_stats = ZKStatsUserspace {
        proofs_generated: total_proofs,
        proofs_verified: total_verifications,
        verification_failures: engine_stats.verification_failures.load(core::sync::atomic::Ordering::SeqCst),
        circuits_compiled: engine_stats.circuits_compiled.load(core::sync::atomic::Ordering::SeqCst),
        avg_proving_time_ms: if total_proofs > 0 { total_proving_time / total_proofs } else { 0 },
        avg_verification_time_ms: if total_verifications > 0 { total_verification_time / total_verifications } else { 0 },
    };

    // Copy stats to user space
    unsafe {
        *(stats_ptr as *mut ZKStatsUserspace) = user_stats;
    }

    Ok(0) // Success
}
