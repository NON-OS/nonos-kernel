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

use super::extension::GoldilocksExt2;
use super::field::GoldilocksField;
use alloc::vec::Vec;

pub struct FriConfig {
    pub log_blowup: u32,
    pub num_queries: usize,
    pub folding_factor: usize,
    pub final_poly_degree: usize,
}

impl Default for FriConfig {
    fn default() -> Self {
        Self { log_blowup: 3, num_queries: 80, folding_factor: 16, final_poly_degree: 8 }
    }
}

pub struct FriProof {
    pub commit_phase_commits: Vec<[u8; 32]>,
    pub query_round_proofs: Vec<QueryRoundProof>,
    pub final_poly: Vec<GoldilocksExt2>,
}

pub struct QueryRoundProof {
    pub initial_trees_proof: Vec<Vec<[u8; 32]>>,
    pub steps: Vec<FriQueryStep>,
}

pub struct FriQueryStep {
    pub evals: Vec<GoldilocksExt2>,
    pub merkle_proof: Vec<[u8; 32]>,
}

pub struct FriProver {
    config: FriConfig,
}

impl FriProver {
    pub fn new(config: FriConfig) -> Self {
        Self { config }
    }

    pub fn prove(&self, evaluations: &[GoldilocksExt2], domain_size: usize) -> FriProof {
        let mut commit_phase_commits = Vec::new();
        let mut current = evaluations.to_vec();
        let mut current_domain = domain_size;
        while current_domain > self.config.final_poly_degree {
            let commitment = self.commit_layer(&current);
            commit_phase_commits.push(commitment);
            current =
                self.fold_evaluations(&current, GoldilocksField::MULTIPLICATIVE_GROUP_GENERATOR);
            current_domain /= self.config.folding_factor;
        }
        FriProof { commit_phase_commits, query_round_proofs: Vec::new(), final_poly: current }
    }

    fn commit_layer(&self, evaluations: &[GoldilocksExt2]) -> [u8; 32] {
        let mut hash_input = Vec::with_capacity(evaluations.len() * 16);
        for eval in evaluations {
            hash_input.extend_from_slice(&eval.0[0].0.to_le_bytes());
            hash_input.extend_from_slice(&eval.0[1].0.to_le_bytes());
        }
        crate::crypto::sha256(&hash_input)
    }

    fn fold_evaluations(
        &self,
        evals: &[GoldilocksExt2],
        beta: GoldilocksField,
    ) -> Vec<GoldilocksExt2> {
        let half = evals.len() / 2;
        let mut folded = Vec::with_capacity(half);
        let beta_ext = GoldilocksExt2::from_base(beta);
        for i in 0..half {
            let even = evals[i];
            let odd = evals[i + half];
            let combined = even + beta_ext * odd;
            folded.push(combined);
        }
        folded
    }
}

pub struct FriVerifier {
    config: FriConfig,
}

impl FriVerifier {
    pub fn new(config: FriConfig) -> Self {
        Self { config }
    }

    pub fn verify(&self, proof: &FriProof, _domain_size: usize) -> bool {
        if proof.final_poly.len() > self.config.final_poly_degree {
            return false;
        }
        for coeff in &proof.final_poly {
            if coeff.0[0].0 >= super::field::GOLDILOCKS_MODULUS {
                return false;
            }
            if coeff.0[1].0 >= super::field::GOLDILOCKS_MODULUS {
                return false;
            }
        }
        true
    }
}
