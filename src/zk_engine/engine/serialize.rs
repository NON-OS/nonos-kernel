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

use super::super::types::{ZKError, ZKProof};
use super::core::ZKEngine;
use alloc::vec::Vec;

impl ZKEngine {
    pub fn serialize_proof(&self, proof: &ZKProof) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&proof.circuit_id.to_le_bytes());
        let proof_bytes = proof.proof_data.serialize();
        serialized.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        serialized.extend_from_slice(&proof_bytes);
        serialized.extend_from_slice(&(proof.public_inputs.len() as u32).to_le_bytes());
        for input in &proof.public_inputs {
            serialized.extend_from_slice(&(input.len() as u32).to_le_bytes());
            serialized.extend_from_slice(input);
        }
        serialized.extend_from_slice(&proof.proof_hash);
        serialized.extend_from_slice(&proof.created_at.to_le_bytes());
        serialized
    }

    pub fn deserialize_proof(&self, data: &[u8]) -> Result<ZKProof, ZKError> {
        if data.len() < 48 {
            return Err(ZKError::InvalidProof);
        }
        let mut offset = 0;
        let circuit_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        offset += 4;
        let proof_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + proof_len > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let proof_data =
            super::super::groth16::Proof::deserialize(&data[offset..offset + proof_len])?;
        offset += proof_len;
        if offset + 4 > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let num_inputs = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let mut public_inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            if offset + 4 > data.len() {
                return Err(ZKError::InvalidProof);
            }
            let input_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;
            if offset + input_len > data.len() {
                return Err(ZKError::InvalidProof);
            }
            public_inputs.push(data[offset..offset + input_len].to_vec());
            offset += input_len;
        }
        if offset + 32 > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        if offset + 8 > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let created_at = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        Ok(ZKProof { circuit_id, proof_data, public_inputs, proof_hash, created_at })
    }
}
