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

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::syscall::dispatch::{errno, require_capability};

pub fn handle_crypto_zk_prove(
    proof_type: u64,
    secret_ptr: u64,
    public_ptr: u64,
    proof_out_ptr: u64,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }

    if secret_ptr == 0 || public_ptr == 0 || proof_out_ptr == 0 {
        return errno(22);
    }

    match proof_type {
        1 => {
            let secret = unsafe { core::slice::from_raw_parts(secret_ptr as *const u8, 32) };
            let public = unsafe { core::slice::from_raw_parts(public_ptr as *const u8, 32) };
            let proof_out = unsafe { core::slice::from_raw_parts_mut(proof_out_ptr as *mut u8, 64) };

            let mut secret_arr = [0u8; 32];
            let mut public_arr = [0u8; 32];
            secret_arr.copy_from_slice(secret);
            public_arr.copy_from_slice(public);

            match crate::crypto::zk_kernel::syscall_zk_prove_schnorr(&secret_arr, &public_arr) {
                Ok(proof) => {
                    proof_out.copy_from_slice(&proof);
                    SyscallResult { value: 64, capability_consumed: false, audit_required: true }
                }
                Err(_) => errno(5),
            }
        }
        6 => {
            let value = unsafe { core::slice::from_raw_parts(secret_ptr as *const u8, 32) };
            let proof_out = unsafe { core::slice::from_raw_parts_mut(proof_out_ptr as *mut u8, 64) };

            let mut value_arr = [0u8; 32];
            value_arr.copy_from_slice(value);

            match crate::crypto::zk_kernel::syscall_zk_commit(&value_arr) {
                Ok((commitment, blinding)) => {
                    proof_out[..32].copy_from_slice(&commitment);
                    proof_out[32..64].copy_from_slice(&blinding);
                    SyscallResult { value: 64, capability_consumed: false, audit_required: true }
                }
                Err(_) => errno(5),
            }
        }
        _ => errno(22),
    }
}

pub fn handle_crypto_zk_verify(
    proof_type: u64,
    proof_ptr: u64,
    proof_len: u64,
    public_input_ptr: u64,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Crypto) {
        return e;
    }

    if proof_ptr == 0 || public_input_ptr == 0 || proof_len == 0 {
        return errno(22);
    }

    let public_input_len = match proof_type {
        1 => 32,
        2 => 32,
        3 => 0,
        6 => 64,
        _ => return errno(22),
    };

    let proof_data = unsafe { core::slice::from_raw_parts(proof_ptr as *const u8, proof_len as usize) };
    let public_input = if public_input_len > 0 {
        unsafe { core::slice::from_raw_parts(public_input_ptr as *const u8, public_input_len) }
    } else {
        &[]
    };

    match crate::crypto::zk_kernel::syscall_zk_verify(proof_type as u8, proof_data, public_input) {
        Ok(()) => SyscallResult { value: 1, capability_consumed: false, audit_required: true },
        Err(crate::crypto::zk_kernel::ZkError::InvalidProof) => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: true }
        }
        Err(crate::crypto::zk_kernel::ZkError::MalformedInput) => errno(22),
        Err(crate::crypto::zk_kernel::ZkError::UnsupportedProofType) => errno(38),
        Err(_) => errno(5),
    }
}
