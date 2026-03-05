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

//! Groth16 prover and verifier implementation.

extern crate alloc;
use alloc::vec::Vec;

use crate::zk_engine::ZKError;
use crate::zk_engine::circuit::Circuit;
use super::field::FieldElement;
use super::g1::G1Point;
use super::pairing::Pairing;
use super::keys::{ProvingKey, VerifyingKey};
use super::proof::Proof;

/// Groth16 Prover
pub struct Groth16Prover;

impl Groth16Prover {
    /// Create new prover
    pub fn new(_setup: &crate::zk_engine::setup::SetupParameters) -> Result<Self, ZKError> {
        Ok(Groth16Prover)
    }

    /// Generate proving and verifying keys for a circuit
    pub fn generate_keys(circuit: &Circuit) -> Result<(ProvingKey, VerifyingKey), ZKError> {
        // Use trusted setup to generate keys
        let setup = crate::zk_engine::setup::TrustedSetup::setup(circuit)?;
        Ok((setup.proving_key, setup.verifying_key))
    }

    /// Generate a Groth16 proof
    pub fn prove(
        proving_key: &ProvingKey,
        circuit: &Circuit,
        witness: &[FieldElement],
        public_inputs: &[FieldElement],
        circuit_id: u32,
    ) -> Result<Proof, ZKError> {
        // Validate witness length
        if witness.len() != circuit.num_variables {
            return Err(ZKError::InvalidWitness);
        }

        // Validate public inputs
        if public_inputs.len() != circuit.num_inputs {
            return Err(ZKError::InvalidWitness);
        }

        // Generate random values for zero-knowledge
        let r = FieldElement::random();
        let s = FieldElement::random();

        // Compute A = alpha + sum(a_i * w_i) + r*delta
        let mut a_point = proving_key.alpha_g1.clone();
        for (i, w) in witness.iter().enumerate() {
            if i < proving_key.a_query.len() {
                let term = proving_key.a_query[i].scalar_mul(&w.limbs);
                a_point = a_point.add(&term);
            }
        }
        a_point = a_point.add(&proving_key.delta_g1.scalar_mul(&r.limbs));

        // Compute B = beta + sum(b_i * w_i) + s*delta
        let mut b_point_g1 = proving_key.beta_g1.clone();
        let mut b_point_g2 = proving_key.beta_g2.clone();
        for (i, w) in witness.iter().enumerate() {
            if i < proving_key.b_g1_query.len() {
                let term_g1 = proving_key.b_g1_query[i].scalar_mul(&w.limbs);
                let term_g2 = proving_key.b_g2_query[i].scalar_mul(&w.limbs);
                b_point_g1 = b_point_g1.add(&term_g1);
                b_point_g2 = b_point_g2.add(&term_g2);
            }
        }
        b_point_g2 = b_point_g2.add(&proving_key.delta_g2.scalar_mul(&s.limbs));

        // Compute C = sum(l_i * w_i) + h*t(tau) + A*s + r*B - r*s*delta
        let mut c_point = G1Point::identity();

        // Add L query contribution
        for (i, w) in witness.iter().enumerate().skip(circuit.num_inputs + 1) {
            let idx = i - circuit.num_inputs - 1;
            if idx < proving_key.l_query.len() {
                let term = proving_key.l_query[idx].scalar_mul(&w.limbs);
                c_point = c_point.add(&term);
            }
        }

        // Add H polynomial evaluation (simplified)
        // In full implementation: compute h(x) = (A(x)*B(x) - C(x)) / t(x)
        // and evaluate at tau using h_query

        // Add A*s
        c_point = c_point.add(&a_point.scalar_mul(&s.limbs));

        // Add r*B
        c_point = c_point.add(&b_point_g1.scalar_mul(&r.limbs));

        // Subtract r*s*delta
        let rs = r.mul(&s);
        c_point = c_point.add(&proving_key.delta_g1.scalar_mul(&rs.limbs).neg());

        Ok(Proof {
            a: a_point,
            b: b_point_g2,
            c: c_point,
            circuit_id,
        })
    }
}

/// Groth16 Verifier
pub struct Groth16Verifier;

impl Groth16Verifier {
    /// Create new verifier
    pub fn new(_setup: &crate::zk_engine::setup::SetupParameters) -> Result<Self, ZKError> {
        Ok(Groth16Verifier)
    }

    /// Verify a Groth16 proof
    pub fn verify(
        verifying_key: &VerifyingKey,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<bool, ZKError> {
        // Validate public inputs length
        if public_inputs.len() + 1 != verifying_key.ic.len() {
            return Err(ZKError::VerificationFailed);
        }

        // Compute vk_x = IC[0] + sum(public_inputs[i] * IC[i+1])
        let mut vk_x = verifying_key.ic[0].clone();
        for (i, input) in public_inputs.iter().enumerate() {
            let term = verifying_key.ic[i + 1].scalar_mul(&input.limbs);
            vk_x = vk_x.add(&term);
        }

        // Verification equation:
        // e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
        //
        // Rearranged:
        // e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1

        let pairing1 = Pairing::compute(&proof.a, &proof.b);
        let pairing2 = Pairing::compute(&verifying_key.alpha_g1.neg(), &verifying_key.beta_g2);
        let pairing3 = Pairing::compute(&vk_x.neg(), &verifying_key.gamma_g2);
        let pairing4 = Pairing::compute(&proof.c.neg(), &verifying_key.delta_g2);

        let result = pairing1.mul(&pairing2).mul(&pairing3).mul(&pairing4);

        Ok(result.is_identity())
    }

    /// Batch verify multiple proofs
    pub fn batch_verify(
        verifying_key: &VerifyingKey,
        proofs: &[Proof],
        public_inputs: &[Vec<FieldElement>],
    ) -> Result<bool, ZKError> {
        if proofs.len() != public_inputs.len() {
            return Err(ZKError::VerificationFailed);
        }

        // For now, verify each proof individually
        // A real batch verification would use randomization
        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            if !Self::verify(verifying_key, proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
