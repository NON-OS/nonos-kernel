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
use crate::zk_engine::syscalls::helpers::is_valid_user_ptr;
use crate::zk_engine::syscalls::params::*;
use crate::zk_engine::{get_zk_engine, ZKError};
use core::slice;

pub fn sys_zk_verify(
    params_ptr: usize,
    process: &ProcessControlBlock,
) -> Result<usize, &'static str> {
    if !crate::sys::settings::zk_attestation() {
        return Err("ZK attestation disabled in settings");
    }
    if !is_valid_user_ptr(params_ptr, core::mem::size_of::<ZKVerifyParams>(), process) {
        return Err("Invalid parameters pointer");
    }
    let params = unsafe { &*(params_ptr as *const ZKVerifyParams) };
    if params.proof_len > MAX_PROOF_SIZE {
        return Err("Proof size too large");
    }
    if !is_valid_user_ptr(params.proof_ptr as usize, params.proof_len, process) {
        return Err("Invalid proof pointer");
    }
    if !is_valid_user_ptr(params.result_ptr as usize, core::mem::size_of::<bool>(), process) {
        return Err("Invalid result pointer");
    }
    let proof_data = unsafe { slice::from_raw_parts(params.proof_ptr, params.proof_len) };
    let engine = get_zk_engine().map_err(|_| "ZK engine not initialized")?;
    let proof = engine.deserialize_proof(proof_data).map_err(|_| "Invalid proof format")?;
    let start_time = crate::time::timestamp_millis();
    let is_valid = match engine.verify_proof(&proof) {
        Ok(result) => result,
        Err(ZKError::CircuitNotFound) => return Err("Circuit not found"),
        Err(ZKError::VerificationFailed) => return Err("Verification failed"),
        Err(_) => return Err("ZK engine error"),
    };
    let verification_time = crate::time::timestamp_millis() - start_time;
    unsafe {
        *(params.result_ptr) = is_valid;
    }
    process.zk_proofs_verified.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    process
        .zk_verification_time_ms
        .fetch_add(verification_time, core::sync::atomic::Ordering::Relaxed);
    Ok(0)
}
