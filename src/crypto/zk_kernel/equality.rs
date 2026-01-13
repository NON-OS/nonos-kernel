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
use core::ptr;

use crate::crypto::hash::blake3_hash;
use crate::crypto::rng::get_random_bytes;
use crate::crypto::curve25519::EdwardsPoint;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use super::constants::DOM_EQUALITY;
use super::field::FieldElement;
use super::pedersen::PedersenCommitment;

#[derive(Clone, Debug)]
pub struct EqualityProof {
    pub nonce_commitment: [u8; 32],
    pub challenge: [u8; 32],
    pub response: [u8; 32],
}

impl EqualityProof {
    pub fn prove(
        _value: &[u8; 32],
        blinding1: &[u8; 32],
        blinding2: &[u8; 32],
        comm1: &PedersenCommitment,
        comm2: &PedersenCommitment,
    ) -> Self {
        let h = PedersenCommitment::generator_h();
        let k = get_random_bytes();

        let r_point = h.scalar_mul(&k);
        let nonce_commitment = r_point.compress();

        let b1_fe = FieldElement::from_bytes(blinding1);
        let b2_fe = FieldElement::from_bytes(blinding2);
        let diff = b1_fe.sub(&b2_fe);

        let mut transcript = Vec::with_capacity(DOM_EQUALITY.len() + 128);
        transcript.extend_from_slice(DOM_EQUALITY);
        transcript.extend_from_slice(&comm1.commitment);
        transcript.extend_from_slice(&comm2.commitment);
        transcript.extend_from_slice(&nonce_commitment);
        let challenge = blake3_hash(&transcript);

        let c_fe = FieldElement::from_bytes(&challenge);
        let k_fe = FieldElement::from_bytes(&k);
        let response = k_fe.add(&c_fe.mul(&diff));
        for b in transcript.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
        compiler_fence();
        memory_fence();

        Self {
            nonce_commitment,
            challenge,
            response: response.to_bytes(),
        }
    }

    // # SECURITY: Constant-time verification using error accumulation
    // Always performs all operations regardless of intermediate results
    pub fn verify(&self, comm1: &PedersenCommitment, comm2: &PedersenCommitment) -> bool {
        let mut valid: u8 = 1;

        let r_point = EdwardsPoint::decompress(&self.nonce_commitment);
        let c1_point = comm1.to_point();
        let c2_point = comm2.to_point();

        valid &= ct_option_is_some(&r_point);
        valid &= ct_option_is_some(&c1_point);
        valid &= ct_option_is_some(&c2_point);

        let r_pt = r_point.unwrap_or_else(EdwardsPoint::identity);
        let c1_pt = c1_point.unwrap_or_else(EdwardsPoint::identity);
        let c2_pt = c2_point.unwrap_or_else(EdwardsPoint::identity);

        let mut transcript = Vec::with_capacity(DOM_EQUALITY.len() + 128);
        transcript.extend_from_slice(DOM_EQUALITY);
        transcript.extend_from_slice(&comm1.commitment);
        transcript.extend_from_slice(&comm2.commitment);
        transcript.extend_from_slice(&self.nonce_commitment);
        let expected_challenge = blake3_hash(&transcript);

        valid &= ct_bytes_eq(&self.challenge, &expected_challenge);

        let h = PedersenCommitment::generator_h();
        let lhs = h.scalar_mul(&self.response);
        let c1_minus_c2 = c1_pt.add(&c2_pt.negate());
        let c_times_diff = c1_minus_c2.scalar_mul(&self.challenge);
        let rhs = r_pt.add(&c_times_diff);

        valid &= ct_bytes_eq(&lhs.compress(), &rhs.compress());

        valid == 1
    }
}

// # SECURITY: Constant-time check if Option is Some returns 1 if Some, 0 if None
#[inline]
fn ct_option_is_some<T>(opt: &Option<T>) -> u8 {
    match opt {
        Some(_) => 1,
        None => 0,
    }
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
