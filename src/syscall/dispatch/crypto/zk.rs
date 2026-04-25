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

extern crate alloc;

use crate::capabilities::Capability;
use crate::syscall::dispatch::{errno, require_capability};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

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
            let mut secret_arr = [0u8; 32];
            let mut public_arr = [0u8; 32];
            if copy_from_user(secret_ptr, &mut secret_arr).is_err() {
                return errno(14);
            }
            if copy_from_user(public_ptr, &mut public_arr).is_err() {
                return errno(14);
            }
            match crate::crypto::zk_kernel::syscall_zk_prove_schnorr(&secret_arr, &public_arr) {
                Ok(proof) => {
                    if copy_to_user(proof_out_ptr, &proof).is_err() {
                        return errno(14);
                    }
                    SyscallResult { value: 64, capability_consumed: false, audit_required: true }
                }
                Err(_) => errno(5),
            }
        }
        6 => {
            let mut value_arr = [0u8; 32];
            if copy_from_user(secret_ptr, &mut value_arr).is_err() {
                return errno(14);
            }
            match crate::crypto::zk_kernel::syscall_zk_commit(&value_arr) {
                Ok((commitment, blinding)) => {
                    let mut proof_out = [0u8; 64];
                    proof_out[..32].copy_from_slice(&commitment);
                    proof_out[32..64].copy_from_slice(&blinding);
                    if copy_to_user(proof_out_ptr, &proof_out).is_err() {
                        return errno(14);
                    }
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
    let mut proof_data = alloc::vec![0u8; proof_len as usize];
    if copy_from_user(proof_ptr, &mut proof_data).is_err() {
        return errno(14);
    }
    let public_input = if public_input_len > 0 {
        let mut buf = alloc::vec![0u8; public_input_len];
        if copy_from_user(public_input_ptr, &mut buf).is_err() {
            return errno(14);
        }
        buf
    } else {
        alloc::vec![]
    };
    match crate::crypto::zk_kernel::syscall_zk_verify(proof_type as u8, &proof_data, &public_input)
    {
        Ok(()) => SyscallResult { value: 1, capability_consumed: false, audit_required: true },
        Err(crate::crypto::zk_kernel::ZkError::InvalidProof) => {
            SyscallResult { value: 0, capability_consumed: false, audit_required: true }
        }
        Err(crate::crypto::zk_kernel::ZkError::MalformedInput) => errno(22),
        Err(crate::crypto::zk_kernel::ZkError::UnsupportedProofType) => errno(38),
        Err(_) => errno(5),
    }
}
