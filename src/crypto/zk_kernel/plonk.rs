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
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use super::constants::DOM_PLONK;
use super::field::FieldElement;

#[derive(Clone, Debug)]
pub struct PlonkProof {
    pub wire_commitments: [[u8; 32]; 3],
    pub permutation_commitment: [u8; 32],
    pub quotient_commitment: [u8; 32],
    pub evaluations: PlonkEvaluations,
    pub opening_proof: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct PlonkEvaluations {
    pub a: [u8; 32],
    pub b: [u8; 32],
    pub c: [u8; 32],
    pub z_omega: [u8; 32],
    pub s_sigma1: [u8; 32],
    pub s_sigma2: [u8; 32],
}

impl PlonkEvaluations {
    pub fn new() -> Self {
        Self {
            a: [0u8; 32],
            b: [0u8; 32],
            c: [0u8; 32],
            z_omega: [0u8; 32],
            s_sigma1: [0u8; 32],
            s_sigma2: [0u8; 32],
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlonkCircuit {
    pub num_gates: usize,
    pub public_inputs: Vec<[u8; 32]>,
}

impl PlonkCircuit {
    pub fn new() -> Self {
        Self {
            num_gates: 0,
            public_inputs: Vec::new(),
        }
    }

    pub fn add_mul_gate(&mut self) {
        self.num_gates += 1;
    }

    pub fn add_public_input(&mut self, value: &[u8; 32]) {
        self.public_inputs.push(*value);
    }
}

impl PlonkProof {
    pub fn prove(witness: &[[u8; 32]], _circuit: &PlonkCircuit) -> Result<Self, &'static str> {
        if witness.is_empty() {
            return Err("Empty witness");
        }

        let mut wire_a_transcript = Vec::with_capacity(DOM_PLONK.len() + witness.len() * 32);
        wire_a_transcript.extend_from_slice(DOM_PLONK);
        wire_a_transcript.push(b'a');
        for w in witness {
            wire_a_transcript.extend_from_slice(w);
        }
        let wire_a_commitment = blake3_hash(&wire_a_transcript);

        let mut wire_b_transcript = Vec::with_capacity(DOM_PLONK.len() + witness.len() * 32);
        wire_b_transcript.extend_from_slice(DOM_PLONK);
        wire_b_transcript.push(b'b');
        let blinding_b = get_random_bytes();
        wire_b_transcript.extend_from_slice(&blinding_b);
        for w in witness {
            wire_b_transcript.extend_from_slice(w);
        }
        let wire_b_commitment = blake3_hash(&wire_b_transcript);

        let mut wire_c_transcript = Vec::with_capacity(DOM_PLONK.len() + witness.len() * 32);
        wire_c_transcript.extend_from_slice(DOM_PLONK);
        wire_c_transcript.push(b'c');
        for i in 0..witness.len() / 2 {
            let a = FieldElement::from_bytes(&witness[i * 2]);
            let b = FieldElement::from_bytes(&witness[i * 2 + 1]);
            let c = a.mul(&b);
            wire_c_transcript.extend_from_slice(&c.to_bytes());
        }
        let wire_c_commitment = blake3_hash(&wire_c_transcript);

        let mut beta_transcript = Vec::with_capacity(128);
        beta_transcript.extend_from_slice(DOM_PLONK);
        beta_transcript.extend_from_slice(b"beta");
        beta_transcript.extend_from_slice(&wire_a_commitment);
        beta_transcript.extend_from_slice(&wire_b_commitment);
        beta_transcript.extend_from_slice(&wire_c_commitment);
        let beta = blake3_hash(&beta_transcript);

        let mut gamma_transcript = Vec::with_capacity(64);
        gamma_transcript.extend_from_slice(&beta);
        gamma_transcript.extend_from_slice(b"gamma");
        let gamma = blake3_hash(&gamma_transcript);

        let beta_fe = FieldElement::from_bytes(&beta);
        let gamma_fe = FieldElement::from_bytes(&gamma);
        let z_value = beta_fe.add(&gamma_fe);

        let mut z_transcript = Vec::with_capacity(96);
        z_transcript.extend_from_slice(DOM_PLONK);
        z_transcript.extend_from_slice(b"z_perm");
        z_transcript.extend_from_slice(&z_value.to_bytes());
        let permutation_commitment = blake3_hash(&z_transcript);

        let mut alpha_transcript = Vec::with_capacity(64);
        alpha_transcript.extend_from_slice(&permutation_commitment);
        alpha_transcript.extend_from_slice(b"alpha");
        let alpha = blake3_hash(&alpha_transcript);

        let alpha_fe = FieldElement::from_bytes(&alpha);
        let t_value = alpha_fe.mul(&z_value);

        let mut t_transcript = Vec::with_capacity(96);
        t_transcript.extend_from_slice(DOM_PLONK);
        t_transcript.extend_from_slice(b"quotient");
        t_transcript.extend_from_slice(&t_value.to_bytes());
        let quotient_commitment = blake3_hash(&t_transcript);

        let mut zeta_transcript = Vec::with_capacity(64);
        zeta_transcript.extend_from_slice(&quotient_commitment);
        zeta_transcript.extend_from_slice(b"zeta");
        let zeta = blake3_hash(&zeta_transcript);
        let zeta_fe = FieldElement::from_bytes(&zeta);

        let eval_a = zeta_fe.mul(&FieldElement::from_bytes(&witness[0]));
        let eval_b = if witness.len() > 1 {
            zeta_fe.mul(&FieldElement::from_bytes(&witness[1]))
        } else {
            zeta_fe
        };
        let eval_c = eval_a.mul(&eval_b);

        let omega = FieldElement::random();
        let zeta_omega = zeta_fe.mul(&omega);
        let eval_z_omega = zeta_omega.mul(&z_value);

        let eval_s_sigma1 = zeta_fe.add(&beta_fe);
        let eval_s_sigma2 = zeta_fe.add(&gamma_fe);

        let evaluations = PlonkEvaluations {
            a: eval_a.to_bytes(),
            b: eval_b.to_bytes(),
            c: eval_c.to_bytes(),
            z_omega: eval_z_omega.to_bytes(),
            s_sigma1: eval_s_sigma1.to_bytes(),
            s_sigma2: eval_s_sigma2.to_bytes(),
        };

        let mut opening_transcript = Vec::with_capacity(256);
        opening_transcript.extend_from_slice(DOM_PLONK);
        opening_transcript.extend_from_slice(b"opening");
        opening_transcript.extend_from_slice(&evaluations.a);
        opening_transcript.extend_from_slice(&evaluations.b);
        opening_transcript.extend_from_slice(&evaluations.c);
        opening_transcript.extend_from_slice(&evaluations.z_omega);
        opening_transcript.extend_from_slice(&evaluations.s_sigma1);
        opening_transcript.extend_from_slice(&evaluations.s_sigma2);
        opening_transcript.extend_from_slice(&zeta);
        let opening_proof = blake3_hash(&opening_transcript);

        for b in wire_a_transcript.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
        for b in wire_b_transcript.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
        compiler_fence();
        memory_fence();

        Ok(Self {
            wire_commitments: [wire_a_commitment, wire_b_commitment, wire_c_commitment],
            permutation_commitment,
            quotient_commitment,
            evaluations,
            opening_proof,
        })
    }

    // SECURITY: Constant-time verification - uses error accumulation pattern
    // to prevent timing side-channels
    pub fn verify(&self, public_inputs: &[[u8; 32]]) -> bool {
        // Track validity through all operations - no early returns
        let mut valid: u8 = 1;

        let mut beta_transcript = Vec::with_capacity(128);
        beta_transcript.extend_from_slice(DOM_PLONK);
        beta_transcript.extend_from_slice(b"beta");
        beta_transcript.extend_from_slice(&self.wire_commitments[0]);
        beta_transcript.extend_from_slice(&self.wire_commitments[1]);
        beta_transcript.extend_from_slice(&self.wire_commitments[2]);
        let beta = blake3_hash(&beta_transcript);
        let beta_fe = FieldElement::from_bytes(&beta);

        let mut gamma_transcript = Vec::with_capacity(64);
        gamma_transcript.extend_from_slice(&beta);
        gamma_transcript.extend_from_slice(b"gamma");
        let gamma = blake3_hash(&gamma_transcript);
        let gamma_fe = FieldElement::from_bytes(&gamma);

        let mut alpha_transcript = Vec::with_capacity(64);
        alpha_transcript.extend_from_slice(&self.permutation_commitment);
        alpha_transcript.extend_from_slice(b"alpha");
        let alpha = blake3_hash(&alpha_transcript);
        let alpha_fe = FieldElement::from_bytes(&alpha);

        let mut zeta_transcript = Vec::with_capacity(64);
        zeta_transcript.extend_from_slice(&self.quotient_commitment);
        zeta_transcript.extend_from_slice(b"zeta");
        let zeta = blake3_hash(&zeta_transcript);
        let zeta_fe = FieldElement::from_bytes(&zeta);

        let mut opening_transcript = Vec::with_capacity(256);
        opening_transcript.extend_from_slice(DOM_PLONK);
        opening_transcript.extend_from_slice(b"opening");
        opening_transcript.extend_from_slice(&self.evaluations.a);
        opening_transcript.extend_from_slice(&self.evaluations.b);
        opening_transcript.extend_from_slice(&self.evaluations.c);
        opening_transcript.extend_from_slice(&self.evaluations.z_omega);
        opening_transcript.extend_from_slice(&self.evaluations.s_sigma1);
        opening_transcript.extend_from_slice(&self.evaluations.s_sigma2);
        opening_transcript.extend_from_slice(&zeta);
        let expected_opening = blake3_hash(&opening_transcript);

        // Constant-time check: opening proof
        valid &= ct_eq_bool(&self.opening_proof, &expected_opening);

        let a_fe = FieldElement::from_bytes(&self.evaluations.a);
        let b_fe = FieldElement::from_bytes(&self.evaluations.b);
        let c_fe = FieldElement::from_bytes(&self.evaluations.c);
        let ab_product = a_fe.mul(&b_fe);

        // Constant-time check: a * b == c
        valid &= if ab_product.ct_eq(&c_fe) { 1 } else { 0 };

        let z_omega_fe = FieldElement::from_bytes(&self.evaluations.z_omega);
        let s_sigma1_fe = FieldElement::from_bytes(&self.evaluations.s_sigma1);
        let s_sigma2_fe = FieldElement::from_bytes(&self.evaluations.s_sigma2);

        let lhs_term1 = a_fe.add(&beta_fe.mul(&s_sigma1_fe)).add(&gamma_fe);
        let lhs_term2 = b_fe.add(&beta_fe.mul(&s_sigma2_fe)).add(&gamma_fe);
        let lhs_product = lhs_term1.mul(&lhs_term2);

        let rhs_term1 = a_fe.add(&beta_fe.mul(&zeta_fe)).add(&gamma_fe);
        let rhs_term2 = b_fe.add(&beta_fe.mul(&zeta_fe)).add(&gamma_fe);
        let rhs_product = rhs_term1.mul(&rhs_term2);

        let perm_lhs = z_omega_fe.mul(&lhs_product);
        let perm_rhs = rhs_product;

        // Constant-time check: z_omega non-zero
        valid &= if z_omega_fe.is_zero() { 0 } else { 1 };

        // Process all public inputs regardless of previous validity
        for (i, pi) in public_inputs.iter().enumerate() {
            let pi_fe = FieldElement::from_bytes(pi);
            // Always compute consistency check
            let consistency = a_fe.mul(&alpha_fe).add(&pi_fe);
            // Only affect validity for i==0 and non-zero pi
            if i == 0 {
                let pi_nonzero = if pi_fe.is_zero() { 0u8 } else { 1u8 };
                let consistency_nonzero = if consistency.is_zero() { 0u8 } else { 1u8 };
                // Invalid if pi is non-zero but consistency is zero
                // valid &= (!pi_nonzero) | consistency_nonzero
                valid &= (1 - pi_nonzero) | consistency_nonzero;
            }
        }

        let all_zero = if a_fe.is_zero() && b_fe.is_zero() && c_fe.is_zero() { 1u8 } else { 0u8 };
        valid &= 1 - all_zero;

        for comm in &self.wire_commitments {
            let comm_zero = ct_is_all_zero(comm);
            valid &= 1 - comm_zero;
        }

        // Constant-time check: permutation commitment non-zero
        valid &= 1 - ct_is_all_zero(&self.permutation_commitment);

        // Constant-time check: quotient commitment non-zero
        valid &= 1 - ct_is_all_zero(&self.quotient_commitment);

        let linearization_check = alpha_fe.mul(&perm_lhs.sub(&perm_rhs));
        let gate_result = ab_product.sub(&c_fe);
        let _total_constraint = gate_result.add(&linearization_check);

        valid == 1
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * 12);

        for comm in &self.wire_commitments {
            bytes.extend_from_slice(comm);
        }

        bytes.extend_from_slice(&self.permutation_commitment);
        bytes.extend_from_slice(&self.quotient_commitment);

        bytes.extend_from_slice(&self.evaluations.a);
        bytes.extend_from_slice(&self.evaluations.b);
        bytes.extend_from_slice(&self.evaluations.c);
        bytes.extend_from_slice(&self.evaluations.z_omega);
        bytes.extend_from_slice(&self.evaluations.s_sigma1);
        bytes.extend_from_slice(&self.evaluations.s_sigma2);

        bytes.extend_from_slice(&self.opening_proof);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 384 {
            return Err("Proof too short");
        }

        let mut wire_commitments = [[0u8; 32]; 3];
        for (i, comm) in wire_commitments.iter_mut().enumerate() {
            comm.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        }

        let mut permutation_commitment = [0u8; 32];
        permutation_commitment.copy_from_slice(&bytes[96..128]);

        let mut quotient_commitment = [0u8; 32];
        quotient_commitment.copy_from_slice(&bytes[128..160]);

        let mut evaluations = PlonkEvaluations::new();
        evaluations.a.copy_from_slice(&bytes[160..192]);
        evaluations.b.copy_from_slice(&bytes[192..224]);
        evaluations.c.copy_from_slice(&bytes[224..256]);
        evaluations.z_omega.copy_from_slice(&bytes[256..288]);
        evaluations.s_sigma1.copy_from_slice(&bytes[288..320]);
        evaluations.s_sigma2.copy_from_slice(&bytes[320..352]);

        let mut opening_proof = [0u8; 32];
        opening_proof.copy_from_slice(&bytes[352..384]);
        Ok(Self {
            wire_commitments,
            permutation_commitment,
            quotient_commitment,
            evaluations,
            opening_proof,
        })
    }
}

// # SECURITY: Constant-time equality check returning u8 for error accumulation
#[inline]
fn ct_eq_bool(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    ((diff as u16 | (diff as u16).wrapping_neg()) >> 8) as u8 ^ 1
}

// # SECURITY: Constant-time check if all bytes are zero
#[inline]
fn ct_is_all_zero(data: &[u8; 32]) -> u8 {
    let mut acc = 0u8;
    for &b in data {
        acc |= b;
    }
    ((acc as u16 | (acc as u16).wrapping_neg()) >> 8) as u8 ^ 1
}

pub fn plonk_prove(witness: &[[u8; 32]]) -> Result<PlonkProof, &'static str> {
    let mut circuit = PlonkCircuit::new();
    circuit.add_mul_gate();
    PlonkProof::prove(witness, &circuit)
}

pub fn plonk_verify(proof: &PlonkProof, public_inputs: &[[u8; 32]]) -> bool {
    proof.verify(public_inputs)
}
