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
use core::ptr;

use crate::crypto::hash::blake3_hash;
use crate::crypto::rng::get_random_bytes;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
use super::super::constants::DOM_PLONK;
use super::super::field::FieldElement;
use super::types::{PlonkProof, PlonkEvaluations, PlonkCircuit};

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
}

pub fn plonk_prove(witness: &[[u8; 32]]) -> Result<PlonkProof, &'static str> {
    let mut circuit = PlonkCircuit::new();
    circuit.add_mul_gate();
    PlonkProof::prove(witness, &circuit)
}
