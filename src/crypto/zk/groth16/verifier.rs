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

use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey};

use crate::crypto::zk::groth16::deserialize::{public_inputs_from_le_bytes, read_proof, read_vk};
use crate::crypto::zk::groth16::error::Groth16Error;

pub struct Groth16Verifier {
    pvk: PreparedVerifyingKey<Bn254>,
    expected_inputs: usize,
}

impl Groth16Verifier {
    #[must_use = "verifier should be used for verification"]
    pub fn from_bytes(vk_bytes: &[u8]) -> Result<Self, Groth16Error> {
        let vk = read_vk(vk_bytes)?;
        let expected_inputs = vk.gamma_abc_g1.len().saturating_sub(1);
        let pvk = PreparedVerifyingKey::from(vk);
        Ok(Self { pvk, expected_inputs })
    }

    #[inline]
    #[must_use]
    pub fn expected_public_inputs(&self) -> usize {
        self.expected_inputs
    }

    #[must_use = "verification result must be checked"]
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs_fr_le32: &[[u8; 32]],
    ) -> Result<(), Groth16Error> {
        let pi = public_inputs_from_le_bytes(public_inputs_fr_le32)?;

        if pi.len() != self.expected_inputs {
            return Err(Groth16Error::InvalidPublicInput);
        }

        let proof = read_proof(proof_bytes)?;

        match Groth16::<Bn254>::verify_proof(&self.pvk, &proof, &pi) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Groth16Error::VerifyFailed),
            Err(_) => Err(Groth16Error::VerifyFailed),
        }
    }

    #[must_use = "verification result must be checked"]
    pub fn verify_batch(
        &self,
        proofs: &[&[u8]],
        public_inputs_list: &[&[[u8; 32]]],
    ) -> Result<(), Groth16Error> {
        if proofs.len() != public_inputs_list.len() {
            return Err(Groth16Error::InvalidPublicInput);
        }

        for (proof_bytes, pi_le) in proofs.iter().zip(public_inputs_list.iter()) {
            self.verify(proof_bytes, pi_le)?;
        }
        Ok(())
    }
}

#[must_use = "verification result must be checked"]
pub fn groth16_verify_bn254(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_fr_le32: &[[u8; 32]],
) -> Result<(), Groth16Error> {
    let verifier = Groth16Verifier::from_bytes(vk_bytes)?;
    verifier.verify(proof_bytes, public_inputs_fr_le32)
}
