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

use crate::services::ServiceResponse;
use alloc::vec::Vec;

const ERR_INVAL: i32 = -22;

pub(super) fn generate_proof(seq: u32, witness: &[u8]) -> ServiceResponse {
    let nonce = crate::crypto::get_random_bytes();
    let commitment = crate::crypto::commit(witness, &nonce);
    let mut proof = Vec::with_capacity(64);
    proof.extend_from_slice(&commitment);
    proof.extend_from_slice(&nonce);
    ServiceResponse::ok(seq, proof)
}

pub(super) fn verify_proof(seq: u32, data: &[u8]) -> ServiceResponse {
    if data.len() < 68 {
        return ServiceResponse::err(seq, ERR_INVAL);
    }
    let commitment: [u8; 32] = data[..32].try_into().unwrap_or([0u8; 32]);
    let nonce: [u8; 32] = data[32..64].try_into().unwrap_or([0u8; 32]);
    let public_input = &data[64..];
    let valid = crate::crypto::verify_commitment(&commitment, public_input, &nonce);
    ServiceResponse::ok(seq, alloc::vec![valid as u8])
}

pub(super) fn create_attestation(seq: u32, claim: &[u8]) -> ServiceResponse {
    let nonce = crate::crypto::get_random_bytes();
    let commitment = crate::crypto::commit(claim, &nonce);
    let mut att = Vec::with_capacity(64);
    att.extend_from_slice(&commitment);
    att.extend_from_slice(&nonce);
    ServiceResponse::ok(seq, att)
}
