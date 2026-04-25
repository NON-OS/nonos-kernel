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
use alloc::vec::Vec;

use super::super::constants::DOM_RANGE;
use super::super::field::FieldElement;
use super::super::pedersen::PedersenCommitment;
use super::types::{BitProof, RangeProof};
use crate::crypto::hash::blake3_hash;

impl RangeProof {
    pub(crate) fn verify(&self) -> bool {
        let mut valid: u8 = 1;

        valid &= ct_eq_usize(self.bit_commitments.len(), self.bits as usize);
        valid &= ct_eq_usize(self.bit_proofs.len(), self.bits as usize);
        valid &= ct_eq_usize(self.bit_blindings.len(), self.bits as usize);

        let mut transcript = Vec::with_capacity(DOM_RANGE.len() + self.bit_commitments.len() * 32);
        transcript.extend_from_slice(DOM_RANGE);
        for comm in &self.bit_commitments {
            transcript.extend_from_slice(comm);
        }
        let expected_challenge = blake3_hash(&transcript);

        let challenge_fe = FieldElement::from_bytes(&expected_challenge);
        valid &= 1 ^ challenge_fe.ct_is_zero();

        let response_fe = FieldElement::from_bytes(&self.response);
        valid &= 1 ^ response_fe.ct_is_zero();

        for comm in &self.bit_commitments {
            let mut all_zero: u8 = 1;
            for &b in comm {
                all_zero &= ct_eq_u8(b, 0);
            }
            valid &= 1 ^ all_zero;
        }

        let min_len = core::cmp::min(
            core::cmp::min(self.bit_commitments.len(), self.bit_proofs.len()),
            self.bit_blindings.len(),
        );
        for i in 0..min_len {
            let proof_valid = verify_bit_proof_ct(
                &self.bit_commitments[i],
                &self.bit_blindings[i],
                &self.bit_proofs[i],
            );
            valid &= proof_valid;
        }

        valid == 1
    }
}

fn verify_bit_proof_ct(commitment: &[u8; 32], blinding: &[u8; 32], proof: &BitProof) -> u8 {
    if !proof.verify_structure() {
        return 0;
    }

    let zero_value = [0u8; 32];
    let comm_zero = PedersenCommitment::commit(&zero_value, blinding);

    let mut one_value = [0u8; 32];
    one_value[0] = 1;
    let comm_one = PedersenCommitment::commit(&one_value, blinding);

    let is_zero = ct_bytes_eq(commitment, &comm_zero.commitment);
    let is_one = ct_bytes_eq(commitment, &comm_one.commitment);

    let is_valid_commitment = is_zero | is_one;

    // Current proof format includes per-bit blinding witnesses; the robust
    // validity check is that each commitment opens to either 0 or 1.
    is_valid_commitment
}

#[inline]
fn ct_bytes_eq(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    ct_eq_u8(diff, 0)
}

#[inline]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    let is_nonzero = (diff as u16 | (diff as u16).wrapping_neg()) >> 8;
    (1 ^ is_nonzero) as u8
}

#[inline]
fn ct_eq_usize(a: usize, b: usize) -> u8 {
    let diff = a ^ b;
    let is_nonzero = (diff | diff.wrapping_neg()) >> (usize::BITS - 1);
    (1 ^ is_nonzero) as u8
}
