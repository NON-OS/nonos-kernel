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
use crate::crypto::rng::get_random_bytes;
use super::super::constants::DOM_RANGE;
use super::super::field::FieldElement;
use super::super::pedersen::PedersenCommitment;
use super::types::{BitProof, RangeProof};

impl RangeProof {
    pub(crate) fn prove(value: u64, bits: u8) -> Result<Self, &'static str> {
        if bits > 64 {
            return Err("bits must be <= 64");
        }

        if bits < 64 && value >= (1u64 << bits) {
            return Err("value out of range");
        }

        let mut bit_commitments = Vec::with_capacity(bits as usize);
        let mut bit_blindings = Vec::with_capacity(bits as usize);
        let mut bit_proofs = Vec::with_capacity(bits as usize);
        let mut total_blinding = FieldElement::ZERO;

        for i in 0..bits {
            let bit = ((value >> i) & 1) as u8;
            let blinding = get_random_bytes();

            let mut bit_value = [0u8; 32];
            bit_value[0] = bit;
            let comm = PedersenCommitment::commit(&bit_value, &blinding);
            bit_commitments.push(comm.commitment);
            bit_blindings.push(blinding);

            let bit_proof = create_bit_proof(bit, &blinding, &comm.commitment);
            bit_proofs.push(bit_proof);

            total_blinding = total_blinding.add(&FieldElement::from_bytes(&blinding));
        }

        let mut transcript = Vec::with_capacity(DOM_RANGE.len() + bit_commitments.len() * 32);
        transcript.extend_from_slice(DOM_RANGE);
        for comm in &bit_commitments {
            transcript.extend_from_slice(comm);
        }
        let challenge = blake3_hash(&transcript);

        let c_fe = FieldElement::from_bytes(&challenge);
        let response = total_blinding.mul(&c_fe);

        Ok(Self {
            bit_commitments,
            bit_blindings,
            bit_proofs,
            response: response.to_bytes(),
            bits,
        })
    }
}

pub(crate) fn create_bit_proof(bit: u8, blinding: &[u8; 32], commitment: &[u8; 32]) -> BitProof {
    let zero_value = [0u8; 32];
    let comm_zero = PedersenCommitment::commit(&zero_value, blinding);

    let mut one_value = [0u8; 32];
    one_value[0] = 1;
    let comm_one = PedersenCommitment::commit(&one_value, blinding);

    let k = get_random_bytes();
    let sim_e = get_random_bytes();
    let sim_z = get_random_bytes();

    let mut transcript = Vec::with_capacity(DOM_RANGE.len() + 96);
    transcript.extend_from_slice(DOM_RANGE);
    transcript.extend_from_slice(b"bit_proof");
    transcript.extend_from_slice(commitment);

    if bit == 0 {
        let a0 = blake3_hash(&k);
        transcript.extend_from_slice(&a0);

        let a1 = {
            let mut tmp = Vec::with_capacity(64);
            tmp.extend_from_slice(&sim_z);
            tmp.extend_from_slice(&comm_one.commitment);
            blake3_hash(&tmp)
        };
        transcript.extend_from_slice(&a1);

        let e = blake3_hash(&transcript);
        let e_fe = FieldElement::from_bytes(&e);
        let sim_e_fe = FieldElement::from_bytes(&sim_e);

        let e0_fe = e_fe.sub(&sim_e_fe);
        let e0 = e0_fe.to_bytes();
        let e1 = sim_e;

        let k_fe = FieldElement::from_bytes(&k);
        let blinding_fe = FieldElement::from_bytes(blinding);
        let z0_fe = k_fe.add(&e0_fe.mul(&blinding_fe));
        let z0 = z0_fe.to_bytes();
        let z1 = sim_z;

        BitProof::new(e0, e1, z0, z1)
    } else {
        let a0 = {
            let mut tmp = Vec::with_capacity(64);
            tmp.extend_from_slice(&sim_z);
            tmp.extend_from_slice(&comm_zero.commitment);
            blake3_hash(&tmp)
        };
        transcript.extend_from_slice(&a0);

        let a1 = blake3_hash(&k);
        transcript.extend_from_slice(&a1);

        let e = blake3_hash(&transcript);
        let e_fe = FieldElement::from_bytes(&e);
        let sim_e_fe = FieldElement::from_bytes(&sim_e);

        let e0 = sim_e;
        let e1_fe = e_fe.sub(&sim_e_fe);
        let e1 = e1_fe.to_bytes();

        let k_fe = FieldElement::from_bytes(&k);
        let blinding_fe = FieldElement::from_bytes(blinding);
        let z1_fe = k_fe.add(&e1_fe.mul(&blinding_fe));
        let z0 = sim_z;
        let z1 = z1_fe.to_bytes();

        BitProof::new(e0, e1, z0, z1)
    }
}
