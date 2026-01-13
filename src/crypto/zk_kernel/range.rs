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
use crate::crypto::rng::get_random_bytes;
use super::constants::DOM_RANGE;
use super::field::FieldElement;
use super::pedersen::PedersenCommitment;

#[derive(Clone, Debug)]
pub struct BitProof {
    pub e0: [u8; 32],
    pub e1: [u8; 32],
    pub z0: [u8; 32],
    pub z1: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RangeProof {
    pub bit_commitments: Vec<[u8; 32]>,
    pub bit_blindings: Vec<[u8; 32]>,
    pub bit_proofs: Vec<BitProof>,
    pub response: [u8; 32],
    pub bits: u8,
}

impl RangeProof {
    pub fn prove(value: u64, bits: u8) -> Result<Self, &'static str> {
        if bits > 64 {
            return Err("bits must be <= 64");
        }

        if bits < 64 && value >= (1u64 << bits) {
            return Err("value out of range");
        }

        let mut bit_commitments = Vec::with_capacity(bits as usize);
        let mut bit_blindings = Vec::with_capacity(bits as usize);
        let mut bit_proofs = Vec::with_capacity(bits as usize);
        let mut total_blinding = FieldElement::ZERO;

        for i in 0..bits {
            let bit = ((value >> i) & 1) as u8;
            let blinding = get_random_bytes();

            let mut bit_value = [0u8; 32];
            bit_value[0] = bit;
            let comm = PedersenCommitment::commit(&bit_value, &blinding);
            bit_commitments.push(comm.commitment);
            bit_blindings.push(blinding);

            let bit_proof = Self::create_bit_proof(bit, &blinding, &comm.commitment);
            bit_proofs.push(bit_proof);

            total_blinding = total_blinding.add(&FieldElement::from_bytes(&blinding));
        }

        let mut transcript = Vec::with_capacity(DOM_RANGE.len() + bit_commitments.len() * 32);
        transcript.extend_from_slice(DOM_RANGE);
        for comm in &bit_commitments {
            transcript.extend_from_slice(comm);
        }
        let challenge = blake3_hash(&transcript);

        let c_fe = FieldElement::from_bytes(&challenge);
        let response = total_blinding.mul(&c_fe);

        Ok(Self {
            bit_commitments,
            bit_blindings,
            bit_proofs,
            response: response.to_bytes(),
            bits,
        })
    }

    fn create_bit_proof(bit: u8, blinding: &[u8; 32], commitment: &[u8; 32]) -> BitProof {
        let zero_value = [0u8; 32];
        let comm_zero = PedersenCommitment::commit(&zero_value, blinding);

        let mut one_value = [0u8; 32];
        one_value[0] = 1;
        let comm_one = PedersenCommitment::commit(&one_value, blinding);

        let k = get_random_bytes();
        let sim_e = get_random_bytes();
        let sim_z = get_random_bytes();

        let mut transcript = Vec::with_capacity(DOM_RANGE.len() + 96);
        transcript.extend_from_slice(DOM_RANGE);
        transcript.extend_from_slice(b"bit_proof");
        transcript.extend_from_slice(commitment);

        if bit == 0 {
            let a0 = blake3_hash(&k);
            transcript.extend_from_slice(&a0);

            let a1 = {
                let mut tmp = Vec::with_capacity(64);
                tmp.extend_from_slice(&sim_z);
                tmp.extend_from_slice(&comm_one.commitment);
                blake3_hash(&tmp)
            };
            transcript.extend_from_slice(&a1);

            let e = blake3_hash(&transcript);
            let e_fe = FieldElement::from_bytes(&e);
            let sim_e_fe = FieldElement::from_bytes(&sim_e);

            let e0_fe = e_fe.sub(&sim_e_fe);
            let e0 = e0_fe.to_bytes();
            let e1 = sim_e;

            let k_fe = FieldElement::from_bytes(&k);
            let blinding_fe = FieldElement::from_bytes(blinding);
            let z0_fe = k_fe.add(&e0_fe.mul(&blinding_fe));
            let z0 = z0_fe.to_bytes();
            let z1 = sim_z;

            BitProof { e0, e1, z0, z1 }
        } else {
            let a0 = {
                let mut tmp = Vec::with_capacity(64);
                tmp.extend_from_slice(&sim_z);
                tmp.extend_from_slice(&comm_zero.commitment);
                blake3_hash(&tmp)
            };
            transcript.extend_from_slice(&a0);

            let a1 = blake3_hash(&k);
            transcript.extend_from_slice(&a1);

            let e = blake3_hash(&transcript);
            let e_fe = FieldElement::from_bytes(&e);
            let sim_e_fe = FieldElement::from_bytes(&sim_e);

            let e0 = sim_e;
            let e1_fe = e_fe.sub(&sim_e_fe);
            let e1 = e1_fe.to_bytes();

            let k_fe = FieldElement::from_bytes(&k);
            let blinding_fe = FieldElement::from_bytes(blinding);
            let z1_fe = k_fe.add(&e1_fe.mul(&blinding_fe));
            let z0 = sim_z;
            let z1 = z1_fe.to_bytes();

            BitProof { e0, e1, z0, z1 }
        }
    }

    // # SECURITY: Constant-time verification using error accumulation
    // No early returns to prevent timing side-channels
    pub fn verify(&self) -> bool {
        let mut valid: u8 = 1;

        valid &= ct_eq_usize(self.bit_commitments.len(), self.bits as usize);
        valid &= ct_eq_usize(self.bit_proofs.len(), self.bits as usize);
        valid &= ct_eq_usize(self.bit_blindings.len(), self.bits as usize);

        let mut transcript = Vec::with_capacity(DOM_RANGE.len() + self.bit_commitments.len() * 32);
        transcript.extend_from_slice(DOM_RANGE);
        for comm in &self.bit_commitments {
            transcript.extend_from_slice(comm);
        }
        let _expected_challenge = blake3_hash(&transcript);

        let response_fe = FieldElement::from_bytes(&self.response);
        // Constant-time zero check
        valid &= 1 ^ response_fe.ct_is_zero();

        for comm in &self.bit_commitments {
            let mut all_zero: u8 = 1;
            for &b in comm {
                all_zero &= ct_eq_u8(b, 0);
            }
            valid &= 1 ^ all_zero; // invalid if all zeros
        }

        // Verify all bit proofs (always iterate all, accumulate result)
        let min_len = core::cmp::min(
            core::cmp::min(self.bit_commitments.len(), self.bit_proofs.len()),
            self.bit_blindings.len()
        );
        for i in 0..min_len {
            let proof_valid = self.verify_bit_proof_ct(
                &self.bit_commitments[i],
                &self.bit_blindings[i],
                &self.bit_proofs[i]
            );
            valid &= proof_valid;
        }

        valid == 1
    }

    fn verify_bit_proof(&self, commitment: &[u8; 32], blinding: &[u8; 32], proof: &BitProof) -> bool {
        self.verify_bit_proof_ct(commitment, blinding, proof) == 1
    }

    // # SECURITY: Constant-time bit proof verification
    fn verify_bit_proof_ct(&self, commitment: &[u8; 32], blinding: &[u8; 32], proof: &BitProof) -> u8 {
        let zero_value = [0u8; 32];
        let comm_zero = PedersenCommitment::commit(&zero_value, blinding);

        let mut one_value = [0u8; 32];
        one_value[0] = 1;
        let comm_one = PedersenCommitment::commit(&one_value, blinding);

        let is_zero = ct_bytes_eq(commitment, &comm_zero.commitment);
        let is_one = ct_bytes_eq(commitment, &comm_one.commitment);

        let is_valid_commitment = is_zero | is_one;

        let e0_fe = FieldElement::from_bytes(&proof.e0);
        let e1_fe = FieldElement::from_bytes(&proof.e1);
        let z0_fe = FieldElement::from_bytes(&proof.z0);
        let z1_fe = FieldElement::from_bytes(&proof.z1);
        let blinding_fe = FieldElement::from_bytes(blinding);

        let a0_real = {
            let k0_fe = z0_fe.sub(&e0_fe.mul(&blinding_fe));
            blake3_hash(&k0_fe.to_bytes())
        };

        let a0_sim = {
            let mut tmp = Vec::with_capacity(64);
            tmp.extend_from_slice(&proof.z0);
            tmp.extend_from_slice(&comm_zero.commitment);
            blake3_hash(&tmp)
        };

        let a1_real = {
            let k1_fe = z1_fe.sub(&e1_fe.mul(&blinding_fe));
            blake3_hash(&k1_fe.to_bytes())
        };

        let a1_sim = {
            let mut tmp = Vec::with_capacity(64);
            tmp.extend_from_slice(&proof.z1);
            tmp.extend_from_slice(&comm_one.commitment);
            blake3_hash(&tmp)
        };

        let mut transcript = Vec::with_capacity(DOM_RANGE.len() + 96);
        transcript.extend_from_slice(DOM_RANGE);
        transcript.extend_from_slice(b"bit_proof");
        transcript.extend_from_slice(commitment);

        let mut t1 = transcript.clone();
        t1.extend_from_slice(&a0_real);
        t1.extend_from_slice(&a1_sim);
        let e1_hash = blake3_hash(&t1);
        let e1_fe_hash = FieldElement::from_bytes(&e1_hash);
        let sum = e0_fe.add(&e1_fe);
        let path_zero_valid = sum.ct_eq_u8(&e1_fe_hash) & is_zero;

        let mut t2 = transcript;
        t2.extend_from_slice(&a0_sim);
        t2.extend_from_slice(&a1_real);
        let e2_hash = blake3_hash(&t2);
        let e2_fe_hash = FieldElement::from_bytes(&e2_hash);
        let sum2 = e0_fe.add(&e1_fe);
        let path_one_valid = sum2.ct_eq_u8(&e2_fe_hash) & is_one;

        is_valid_commitment & (path_zero_valid | path_one_valid)
    }
}

// # SECURITY: Constant-time byte equality check
#[inline]
fn ct_bytes_eq(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    ct_eq_u8(diff, 0)
}

// # SECURITY: Constant-time u8 equality - returns 1 if equal, 0 if not
#[inline]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    let is_nonzero = (diff as u16 | (diff as u16).wrapping_neg()) >> 8;
    (1 ^ is_nonzero) as u8
}

// # SECURITY: Constant-time usize equality - returns 1 if equal, 0 if not
#[inline]
fn ct_eq_usize(a: usize, b: usize) -> u8 {
    let diff = a ^ b;
    let is_nonzero = (diff | diff.wrapping_neg()) >> (usize::BITS - 1);
    (1 ^ is_nonzero) as u8
}
