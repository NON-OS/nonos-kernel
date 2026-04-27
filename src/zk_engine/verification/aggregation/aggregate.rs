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

use super::core::ProofAggregator;
use crate::zk_engine::groth16::Proof;
use crate::zk_engine::ZKError;

impl ProofAggregator {
    pub fn aggregate_proofs(proofs: &[Proof]) -> Result<Proof, ZKError> {
        if proofs.is_empty() {
            return Err(ZKError::VerificationFailed);
        }

        if proofs.len() == 1 {
            return Ok(proofs[0].clone());
        }

        let fs_challenge = Self::compute_fs_challenge(proofs);
        let challenges = Self::generate_challenges(&fs_challenge, proofs.len());

        let mut a_agg = proofs[0].a.scalar_mul(&challenges[0].limbs);
        let mut b_agg = proofs[0].b.scalar_mul(&challenges[0].limbs);
        let mut c_agg = proofs[0].c.scalar_mul(&challenges[0].limbs);

        for (i, proof) in proofs.iter().enumerate().skip(1) {
            let a_term = proof.a.scalar_mul(&challenges[i].limbs);
            let b_term = proof.b.scalar_mul(&challenges[i].limbs);
            let c_term = proof.c.scalar_mul(&challenges[i].limbs);

            a_agg = a_agg.add(&a_term);
            b_agg = b_agg.add(&b_term);
            c_agg = c_agg.add(&c_term);
        }

        Ok(Proof { a: a_agg, b: b_agg, c: c_agg, circuit_id: proofs[0].circuit_id })
    }
}
