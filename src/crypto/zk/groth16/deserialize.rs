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

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};

use crate::crypto::zk::groth16::error::Groth16Error;
use crate::crypto::zk::groth16::params;
use crate::crypto::zk::groth16::{MAX_PROOF_BYTES, MAX_PUBLIC_INPUTS, MAX_VK_BYTES};

pub fn read_vk(vk_bytes: &[u8]) -> Result<VerifyingKey<Bn254>, Groth16Error> {
    if vk_bytes.len() > MAX_VK_BYTES {
        return Err(Groth16Error::SizeLimit("verifying key"));
    }

    if vk_bytes.is_empty() {
        return Err(Groth16Error::Deserialize("verifying key: empty input"));
    }

    VerifyingKey::<Bn254>::deserialize_with_mode(vk_bytes, Compress::Yes, Validate::Yes)
        .or_else(|_| {
            VerifyingKey::<Bn254>::deserialize_with_mode(vk_bytes, Compress::No, Validate::Yes)
        })
        .map_err(|_| Groth16Error::Deserialize("verifying key"))
}

pub fn read_proof(proof_bytes: &[u8]) -> Result<Proof<Bn254>, Groth16Error> {
    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(Groth16Error::SizeLimit("proof"));
    }

    if proof_bytes.len() < params::PROOF_SIZE_COMPRESSED {
        return Err(Groth16Error::Deserialize("proof: too short"));
    }

    Proof::<Bn254>::deserialize_with_mode(proof_bytes, Compress::Yes, Validate::Yes)
        .or_else(|_| {
            Proof::<Bn254>::deserialize_with_mode(proof_bytes, Compress::No, Validate::Yes)
        })
        .map_err(|_| Groth16Error::Deserialize("proof"))
}

pub fn public_inputs_from_le_bytes(fr_le32: &[[u8; 32]]) -> Result<Vec<Fr>, Groth16Error> {
    if fr_le32.len() > MAX_PUBLIC_INPUTS {
        return Err(Groth16Error::SizeLimit("public inputs"));
    }

    let mut res = Vec::with_capacity(fr_le32.len());
    for bytes in fr_le32 {
        res.push(Fr::from_le_bytes_mod_order(bytes));
    }

    Ok(res)
}
