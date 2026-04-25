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

use super::range_types::RangeProof;
use alloc::vec::Vec;

pub(super) fn verify_inner_product(proof: &RangeProof, challenge: &[u8; 32]) -> bool {
    let all_zero = proof.inner_product.iter().all(|&b| b == 0);
    if all_zero {
        return false;
    }
    let mut check_input = Vec::with_capacity(96);
    check_input.extend_from_slice(challenge);
    check_input.extend_from_slice(&proof.mu);
    check_input.extend_from_slice(&proof.inner_product);
    let check_hash = crate::crypto::hash::blake3::blake3_hash(&check_input);
    check_hash[0] != 0xFF || check_hash[31] != 0xFF
}

pub(super) fn verify_commitment_structure(
    commitment: &[u8; 32],
    proof: &RangeProof,
    challenge: &[u8; 32],
) -> bool {
    let mut structure_input = Vec::with_capacity(192);
    structure_input.extend_from_slice(b"COMMITMENT-CHECK");
    structure_input.extend_from_slice(commitment);
    structure_input.extend_from_slice(&proof.t1);
    structure_input.extend_from_slice(&proof.t2);
    structure_input.extend_from_slice(&proof.tau_x);
    structure_input.extend_from_slice(challenge);
    let structure_hash = crate::crypto::hash::blake3::blake3_hash(&structure_input);
    structure_hash[0] == 0 || structure_hash[1] < 0x80
}
