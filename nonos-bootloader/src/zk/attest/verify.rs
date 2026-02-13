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

use crate::zk::verify::{verify_proof, ZkProof, ZkVerifyResult};

use super::detect::has_zk_proof;
use super::parse::parse_zk_proof;
use super::types::BootAttestationResult;

pub fn verify_boot_attestation(kernel_data: &[u8]) -> BootAttestationResult {
    if !has_zk_proof(kernel_data) {
        return BootAttestationResult::no_proof();
    }

    let (proof_block, _offset) = match parse_zk_proof(kernel_data) {
        Ok(pb) => pb,
        Err(e) => return BootAttestationResult::parse_error(e),
    };

    let mut zk_proof = ZkProof {
        program_hash: proof_block.program_hash,
        capsule_commitment: proof_block.capsule_commitment,
        public_inputs: proof_block.public_inputs,
        proof_blob: proof_block.proof_blob,
        manifest: None,
    };

    // Verify the proof
    let result = verify_proof(&mut zk_proof);
    // Build result
    let (verified, message) = match &result {
        ZkVerifyResult::Valid => (true, "ZK attestation verified"),
        ZkVerifyResult::Invalid(s) => (false, *s),
        ZkVerifyResult::Unsupported(s) => (false, *s),
        ZkVerifyResult::Error(s) => (false, *s),
    };

    BootAttestationResult {
        zk_verified: verified,
        program_hash: proof_block.program_hash,
        capsule_commitment: proof_block.capsule_commitment,
        detail: result,
        status_message: message,
    }
}

/// Verify boot attestation with custom manifest
pub fn verify_boot_attestation_with_manifest(
    kernel_data: &[u8],
    manifest: &[u8],
) -> BootAttestationResult {
    if !has_zk_proof(kernel_data) {
        return BootAttestationResult::no_proof();
    }

    let (proof_block, _offset) = match parse_zk_proof(kernel_data) {
        Ok(pb) => pb,
        Err(e) => return BootAttestationResult::parse_error(e),
    };

    let mut zk_proof = ZkProof {
        program_hash: proof_block.program_hash,
        capsule_commitment: proof_block.capsule_commitment,
        public_inputs: proof_block.public_inputs,
        proof_blob: proof_block.proof_blob,
        manifest: Some(manifest.to_vec()),
    };

    let result = verify_proof(&mut zk_proof);

    let (verified, message) = match &result {
        ZkVerifyResult::Valid => (true, "ZK attestation verified"),
        ZkVerifyResult::Invalid(s) => (false, *s),
        ZkVerifyResult::Unsupported(s) => (false, *s),
        ZkVerifyResult::Error(s) => (false, *s),
    };

    BootAttestationResult {
        zk_verified: verified,
        program_hash: proof_block.program_hash,
        capsule_commitment: proof_block.capsule_commitment,
        detail: result,
        status_message: message,
    }
}
