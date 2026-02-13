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

use crate::zk::binding::DS_COMMITMENT;
use alloc::vec::Vec;

use super::types::{GROTH16_PROOF_SIZE, ZK_PROOF_HEADER_SIZE, ZK_PROOF_MAGIC, ZK_PROOF_VERSION};

pub fn compute_capsule_commitment(kernel_code: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DS_COMMITMENT);
    hasher.update(kernel_code);
    *hasher.finalize().as_bytes()
}

pub fn create_zk_proof_block(
    program_hash: &[u8; 32],
    capsule_commitment: &[u8; 32],
    public_inputs: &[u8],
    proof_blob: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if proof_blob.len() != GROTH16_PROOF_SIZE {
        return Err("proof blob must be 192 bytes");
    }

    if public_inputs.len() % 32 != 0 {
        return Err("public inputs must be 32-byte aligned");
    }

    let mut block =
        Vec::with_capacity(ZK_PROOF_HEADER_SIZE + public_inputs.len() + proof_blob.len());
    // Header: magic (4) + version (4) + program_hash (32) + commitment (32) + lengths (8) = 80
    block.extend_from_slice(&ZK_PROOF_MAGIC);
    block.extend_from_slice(&ZK_PROOF_VERSION.to_le_bytes());
    block.extend_from_slice(program_hash);
    block.extend_from_slice(capsule_commitment);
    block.extend_from_slice(&(public_inputs.len() as u32).to_le_bytes());
    block.extend_from_slice(&(proof_blob.len() as u32).to_le_bytes());
    // Data
    block.extend_from_slice(public_inputs);
    block.extend_from_slice(proof_blob);

    Ok(block)
}

pub fn calculate_proof_block_size(public_inputs_len: usize) -> usize {
    ZK_PROOF_HEADER_SIZE + public_inputs_len + GROTH16_PROOF_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_proof_magic() {
        assert_eq!(ZK_PROOF_MAGIC[0], b'N');
        assert_eq!(ZK_PROOF_MAGIC[2], b'Z');
        assert_eq!(ZK_PROOF_MAGIC[3], b'P');
    }

    #[test]
    fn test_create_parse_roundtrip() {
        use super::super::parse::parse_zk_proof;
        let program_hash = [0xAAu8; 32];
        let commitment = [0xBBu8; 32];
        let inputs = [0u8; 64];
        let proof = [0u8; 192];
        let block = create_zk_proof_block(&program_hash, &commitment, &inputs, &proof).unwrap();
        let mut kernel = alloc::vec![0u8; 1024];
        kernel.extend_from_slice(&[0u8; 64]); // signature placeholder
        kernel.extend_from_slice(&block);

        use super::super::detect::has_zk_proof;
        assert!(has_zk_proof(&kernel));

        let (parsed, _offset) = parse_zk_proof(&kernel).unwrap();
        assert_eq!(parsed.program_hash, program_hash);
        assert_eq!(parsed.capsule_commitment, commitment);
        assert_eq!(parsed.public_inputs.len(), 64);
        assert_eq!(parsed.proof_blob.len(), 192);
    }
}
