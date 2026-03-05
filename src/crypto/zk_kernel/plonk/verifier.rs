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

use crate::crypto::hash::blake3_hash;
use super::super::constants::DOM_PLONK;
use super::super::field::FieldElement;
use super::types::PlonkProof;
use super::util::{ct_eq_bool, ct_is_all_zero};

impl PlonkProof {
    pub fn verify(&self, public_inputs: &[[u8; 32]]) -> bool {
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

        valid &= ct_eq_bool(&self.opening_proof, &expected_opening);

        let a_fe = FieldElement::from_bytes(&self.evaluations.a);
        let b_fe = FieldElement::from_bytes(&self.evaluations.b);
        let c_fe = FieldElement::from_bytes(&self.evaluations.c);
        let ab_product = a_fe.mul(&b_fe);

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

        valid &= if z_omega_fe.is_zero() { 0 } else { 1 };

        for (i, pi) in public_inputs.iter().enumerate() {
            let pi_fe = FieldElement::from_bytes(pi);
            let consistency = a_fe.mul(&alpha_fe).add(&pi_fe);
            if i == 0 {
                let pi_nonzero = if pi_fe.is_zero() { 0u8 } else { 1u8 };
                let consistency_nonzero = if consistency.is_zero() { 0u8 } else { 1u8 };
                valid &= (1 - pi_nonzero) | consistency_nonzero;
            }
        }

        let all_zero = if a_fe.is_zero() && b_fe.is_zero() && c_fe.is_zero() { 1u8 } else { 0u8 };
        valid &= 1 - all_zero;

        for comm in &self.wire_commitments {
            let comm_zero = ct_is_all_zero(comm);
            valid &= 1 - comm_zero;
        }

        valid &= 1 - ct_is_all_zero(&self.permutation_commitment);
        valid &= 1 - ct_is_all_zero(&self.quotient_commitment);

        let linearization_check = alpha_fe.mul(&perm_lhs.sub(&perm_rhs));
        let gate_result = ab_product.sub(&c_fe);
        let total_constraint = gate_result.add(&linearization_check);

        valid &= if total_constraint.is_zero() { 1u8 } else { 0u8 };

        valid == 1
    }
}

pub fn plonk_verify(proof: &PlonkProof, public_inputs: &[[u8; 32]]) -> bool {
    proof.verify(public_inputs)
}
