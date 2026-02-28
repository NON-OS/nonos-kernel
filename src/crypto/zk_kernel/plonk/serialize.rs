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
use super::types::{PlonkProof, PlonkEvaluations};

impl PlonkProof {
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
