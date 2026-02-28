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
