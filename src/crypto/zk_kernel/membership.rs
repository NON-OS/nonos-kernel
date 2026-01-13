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

use crate::crypto::hash::blake3_hash;
use super::constants::DOM_MERKLE;
use super::field::FieldElement;
use super::pedersen::PedersenCommitment;

#[derive(Clone, Debug)]
pub struct MembershipProof {
    pub path: Vec<[u8; 32]>,
    pub directions: Vec<u8>,
    pub leaf_commitment: [u8; 32],
    pub response: [u8; 32],
}

impl MembershipProof {
    pub fn prove(
        leaf: &[u8; 32],
        leaf_index: usize,
        siblings: &[[u8; 32]],
        blinding: &[u8; 32],
    ) -> Self {
        let leaf_commitment = PedersenCommitment::commit(leaf, blinding).commitment;

        let mut directions = Vec::with_capacity(siblings.len());
        let mut idx = leaf_index;
        for _ in 0..siblings.len() {
            directions.push((idx & 1) as u8);
            idx >>= 1;
        }

        let mut transcript = Vec::with_capacity(DOM_MERKLE.len() + 32 + siblings.len() * 33);
        transcript.extend_from_slice(DOM_MERKLE);
        transcript.extend_from_slice(&leaf_commitment);
        for (sib, dir) in siblings.iter().zip(directions.iter()) {
            transcript.extend_from_slice(sib);
            transcript.push(*dir);
        }
        let challenge = blake3_hash(&transcript);

        let c_fe = FieldElement::from_bytes(&challenge);
        let b_fe = FieldElement::from_bytes(blinding);
        let response = c_fe.mul(&b_fe);

        Self {
            path: siblings.to_vec(),
            directions,
            leaf_commitment,
            response: response.to_bytes(),
        }
    }

    // # SECURITY: Constant-time verification using error accumulation
    // Direction is public info, so direction-based ordering is not a timing leak
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let mut valid: u8 = 1;
        valid &= ct_eq_usize(self.path.len(), self.directions.len());

        let mut current = self.leaf_commitment;
        // Always iterate over the full path
        // Direction is public, so branching on it is acceptable
        for (sibling, &direction) in self.path.iter().zip(self.directions.iter()) {
            let mut combined = Vec::with_capacity(64);
            if direction == 0 {
                combined.extend_from_slice(&current);
                combined.extend_from_slice(sibling);
            } else {
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&current);
            }
            current = blake3_hash(&combined);
        }

        valid &= ct_bytes_eq(&current, root);

        valid == 1
    }
}

// # SECURITY: Constant-time usize equality returns 1 if equal, 0 if not
#[inline]
fn ct_eq_usize(a: usize, b: usize) -> u8 {
    let diff = a ^ b;
    let is_nonzero = (diff | diff.wrapping_neg()) >> (usize::BITS - 1);
    (1 ^ is_nonzero) as u8
}

// # SECURITY: Constant-time byte equality check
#[inline]
fn ct_bytes_eq(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    let is_nonzero = (diff as u16 | (diff as u16).wrapping_neg()) >> 8;
    (1 ^ is_nonzero) as u8
}
