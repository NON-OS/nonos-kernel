// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use alloc::vec::Vec;

use crate::crypto::rng::get_random_bytes;
use super::verifier::{ZkResult, KERNEL_ZK_VERIFIER};
use super::schnorr::SchnorrProof;
use super::pedersen::PedersenCommitment;
use super::plonk::plonk_prove;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkError {
    Success = 0,
    InvalidProof = 1,
    MalformedInput = 2,
    UnsupportedProofType = 3,
    InternalError = 4,
    PermissionDenied = 5,
}

pub fn syscall_zk_verify(
    proof_type: u8,
    proof_data: &[u8],
    public_input: &[u8],
) -> Result<(), ZkError> {
    let mut verifier = KERNEL_ZK_VERIFIER.lock();

    let result = match proof_type {
        1 => {
            if proof_data.len() < 64 || public_input.len() < 32 {
                return Err(ZkError::MalformedInput);
            }
            let mut commitment = [0u8; 32];
            let mut response = [0u8; 32];
            let mut pk = [0u8; 32];
            commitment.copy_from_slice(&proof_data[..32]);
            response.copy_from_slice(&proof_data[32..64]);
            pk.copy_from_slice(&public_input[..32]);
            verifier.verify_schnorr(&commitment, &response, &pk)
        }
        2 => {
            if proof_data.len() < 97 || public_input.len() < 32 {
                return Err(ZkError::MalformedInput);
            }
            let mut a = [0u8; 32];
            let mut e = [0u8; 32];
            let mut z = [0u8; 32];
            let mut statement = [0u8; 32];
            a.copy_from_slice(&proof_data[..32]);
            e.copy_from_slice(&proof_data[32..64]);
            z.copy_from_slice(&proof_data[64..96]);
            let pt = proof_data[96];
            statement.copy_from_slice(&public_input[..32]);
            verifier.verify_sigma(&a, &e, &z, pt, &statement)
        }
        3 => {
            verifier.verify_range(proof_data)
        }
        6 => {
            if proof_data.len() < 32 || public_input.len() < 64 {
                return Err(ZkError::MalformedInput);
            }
            let mut commitment = [0u8; 32];
            let mut value = [0u8; 32];
            let mut blinding = [0u8; 32];
            commitment.copy_from_slice(&proof_data[..32]);
            value.copy_from_slice(&public_input[..32]);
            blinding.copy_from_slice(&public_input[32..64]);
            verifier.verify_commitment(&commitment, &value, &blinding)
        }
        7 => {
            if proof_data.len() < 384 {
                return Err(ZkError::MalformedInput);
            }
            let num_public = public_input.len() / 32;
            let mut pub_inputs = Vec::with_capacity(num_public);
            for i in 0..num_public {
                let mut inp = [0u8; 32];
                inp.copy_from_slice(&public_input[i * 32..(i + 1) * 32]);
                pub_inputs.push(inp);
            }
            verifier.verify_plonk(proof_data, &pub_inputs)
        }
        _ => ZkResult::UnsupportedProofType,
    };

    match result {
        ZkResult::Valid => Ok(()),
        ZkResult::Invalid => Err(ZkError::InvalidProof),
        ZkResult::MalformedProof => Err(ZkError::MalformedInput),
        ZkResult::UnsupportedProofType => Err(ZkError::UnsupportedProofType),
    }
}

pub fn syscall_zk_commit(value: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), ZkError> {
    let blinding = get_random_bytes();
    let comm = PedersenCommitment::commit(value, &blinding);
    Ok((comm.commitment, blinding))
}

pub fn syscall_zk_prove_schnorr(
    secret: &[u8; 32],
    public: &[u8; 32],
) -> Result<[u8; 64], ZkError> {
    let proof = SchnorrProof::prove(secret, public);
    let mut result = [0u8; 64];
    result[..32].copy_from_slice(&proof.commitment);
    result[32..].copy_from_slice(&proof.response);
    Ok(result)
}

pub fn syscall_zk_prove_plonk(witness: &[[u8; 32]]) -> Result<Vec<u8>, ZkError> {
    match plonk_prove(witness) {
        Ok(proof) => Ok(proof.to_bytes()),
        Err(_) => Err(ZkError::InternalError),
    }
}
