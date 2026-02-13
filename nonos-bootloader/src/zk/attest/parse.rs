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

use super::detect::find_zk_proof_offset;
use super::types::{
    ZkProofBlock, GROTH16_PROOF_SIZE, ZK_PROOF_HEADER_SIZE, ZK_PROOF_MAGIC, ZK_PROOF_VERSION,
};

pub fn parse_zk_proof(kernel_data: &[u8]) -> Result<(ZkProofBlock, usize), &'static str> {
    let offset = find_zk_proof_offset(kernel_data).ok_or("ZK proof magic not found")?;
    let block = &kernel_data[offset..];

    if block.len() < ZK_PROOF_HEADER_SIZE {
        return Err("ZK proof block too small");
    }

    if &block[0..4] != &ZK_PROOF_MAGIC {
        return Err("ZK proof magic mismatch");
    }

    let version = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    if version != ZK_PROOF_VERSION {
        return Err("unsupported ZK proof version");
    }

    // Extract program hash (bytes 8-40)
    let mut program_hash = [0u8; 32];
    program_hash.copy_from_slice(&block[8..40]);
    // Extract capsule commitment (bytes 40-72)
    let mut capsule_commitment = [0u8; 32];
    capsule_commitment.copy_from_slice(&block[40..72]);
    // Extract lengths (bytes 72-80)
    let public_inputs_len =
        u32::from_le_bytes([block[72], block[73], block[74], block[75]]) as usize;
    let proof_blob_len = u32::from_le_bytes([block[76], block[77], block[78], block[79]]) as usize;
    // Validate lengths
    if public_inputs_len > 256 * 1024 {
        return Err("public inputs too large");
    }
    if proof_blob_len != GROTH16_PROOF_SIZE {
        return Err("invalid Groth16 proof size");
    }
    if public_inputs_len % 32 != 0 {
        return Err("public inputs not 32-byte aligned");
    }
    // Validate total block size
    let data_start = 80;
    let required_len = data_start + public_inputs_len + proof_blob_len;
    if block.len() < required_len {
        return Err("ZK proof block truncated");
    }
    // Extract data
    let public_inputs = block[data_start..data_start + public_inputs_len].to_vec();
    let proof_blob = block
        [data_start + public_inputs_len..data_start + public_inputs_len + proof_blob_len]
        .to_vec();

    Ok((
        ZkProofBlock {
            program_hash,
            capsule_commitment,
            public_inputs,
            proof_blob,
        },
        offset,
    ))
}

pub fn parse_zk_proof_header(
    kernel_data: &[u8],
) -> Result<([u8; 32], [u8; 32], usize, usize), &'static str> {
    let offset = find_zk_proof_offset(kernel_data).ok_or("ZK proof magic not found")?;
    let block = &kernel_data[offset..];

    if block.len() < ZK_PROOF_HEADER_SIZE {
        return Err("ZK proof block too small");
    }

    let version = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    if version != ZK_PROOF_VERSION {
        return Err("unsupported ZK proof version");
    }

    let mut program_hash = [0u8; 32];
    program_hash.copy_from_slice(&block[8..40]);

    let mut capsule_commitment = [0u8; 32];
    capsule_commitment.copy_from_slice(&block[40..72]);

    let public_inputs_len =
        u32::from_le_bytes([block[72], block[73], block[74], block[75]]) as usize;
    let proof_blob_len = u32::from_le_bytes([block[76], block[77], block[78], block[79]]) as usize;

    Ok((
        program_hash,
        capsule_commitment,
        public_inputs_len,
        proof_blob_len,
    ))
}
