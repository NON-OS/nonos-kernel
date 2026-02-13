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

use crate::zk::errors::ZkError;

#[cfg(feature = "zk-groth16")]
#[derive(Debug)]
pub enum GrothErr {
    VkDeserialize,
    ADeserialize,
    BDeserialize,
    CDeserialize,
    InputsMisaligned,
    InputsCountMismatch,
}

#[cfg(feature = "zk-groth16")]
impl GrothErr {
    pub fn as_str(&self) -> &'static str {
        use GrothErr::*;
        match self {
            VkDeserialize => ZkError::VerifyingKeyDeserialize.as_str(),
            ADeserialize => ZkError::ProofDeserializeA.as_str(),
            BDeserialize => ZkError::ProofDeserializeB.as_str(),
            CDeserialize => ZkError::ProofDeserializeC.as_str(),
            InputsMisaligned => ZkError::InputsMisaligned.as_str(),
            InputsCountMismatch => ZkError::InputsCountMismatch.as_str(),
        }
    }
}

/// Verify Groth16 proof using arkworks BLS12-381
#[cfg(feature = "zk-groth16")]
pub fn groth16_verify(
    vk_bytes: &[u8],
    proof_blob: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool, GrothErr> {
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_ff::PrimeField;
    use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
    use ark_serialize::{CanonicalDeserialize, Compress, Validate};
    use ark_std::io::Cursor;
    // Deserialize verifying key
    let vk = VerifyingKey::<Bls12_381>::deserialize_with_mode(
        &mut Cursor::new(vk_bytes),
        Compress::Yes,
        Validate::Yes,
    )
    .map_err(|_| GrothErr::VkDeserialize)?;

    if public_inputs_bytes.len() % 32 != 0 {
        return Err(GrothErr::InputsMisaligned);
    }

    // Check public inputs count matches VK
    let inputs_count = public_inputs_bytes.len() / 32;
    let expected = vk.gamma_abc_g1.len().saturating_sub(1);
    if inputs_count != expected {
        return Err(GrothErr::InputsCountMismatch);
    }
    // Deserialization
    let mut cur = Cursor::new(proof_blob);
    let a = G1Affine::deserialize_with_mode(&mut cur, Compress::Yes, Validate::Yes)
        .map_err(|_| GrothErr::ADeserialize)?;
    let b = G2Affine::deserialize_with_mode(&mut cur, Compress::Yes, Validate::Yes)
        .map_err(|_| GrothErr::BDeserialize)?;
    let c = G1Affine::deserialize_with_mode(&mut cur, Compress::Yes, Validate::Yes)
        .map_err(|_| GrothErr::CDeserialize)?;

    let proof = Proof::<Bls12_381> { a, b, c };
    let mut inputs = alloc::vec::Vec::with_capacity(inputs_count);
    for chunk in public_inputs_bytes.chunks_exact(32) {
        inputs.push(Fr::from_be_bytes_mod_order(chunk));
    }

    let pvk = prepare_verifying_key(&vk);
    match Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &inputs) {
        Ok(valid) => Ok(valid),
        Err(_) => Ok(false),
    }
}

#[cfg(feature = "zk-groth16")]
extern crate alloc;
