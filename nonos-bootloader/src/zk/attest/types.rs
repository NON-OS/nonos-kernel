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

use crate::zk::verify::ZkVerifyResult;
use alloc::vec::Vec;
/// ZK proof block magic bytes: 'N' 0xC3 'Z' 'P'
pub const ZK_PROOF_MAGIC: [u8; 4] = [0x4E, 0xC3, 0x5A, 0x50];
pub const ZK_PROOF_VERSION: u32 = 1;
pub const ZK_PROOF_HEADER_SIZE: usize = 80;
pub const GROTH16_PROOF_SIZE: usize = 192;

#[derive(Debug, Clone)]
pub struct BootAttestationResult {
    pub zk_verified: bool,
    pub program_hash: [u8; 32],
    pub capsule_commitment: [u8; 32],
    pub detail: ZkVerifyResult,
    pub status_message: &'static str,
}

impl BootAttestationResult {
    pub fn no_proof() -> Self {
        Self {
            zk_verified: false,
            program_hash: [0u8; 32],
            capsule_commitment: [0u8; 32],
            detail: ZkVerifyResult::Unsupported("no ZK proof present"),
            status_message: "no ZK proof present in capsule",
        }
    }

    pub fn parse_error(msg: &'static str) -> Self {
        Self {
            zk_verified: false,
            program_hash: [0u8; 32],
            capsule_commitment: [0u8; 32],
            detail: ZkVerifyResult::Error(msg),
            status_message: msg,
        }
    }

    pub fn verification_failed(
        program_hash: [u8; 32],
        capsule_commitment: [u8; 32],
        msg: &'static str,
    ) -> Self {
        Self {
            zk_verified: false,
            program_hash,
            capsule_commitment,
            detail: ZkVerifyResult::Invalid(msg),
            status_message: msg,
        }
    }

    pub fn verified(program_hash: [u8; 32], capsule_commitment: [u8; 32]) -> Self {
        Self {
            zk_verified: true,
            program_hash,
            capsule_commitment,
            detail: ZkVerifyResult::Valid,
            status_message: "ZK attestation verified",
        }
    }
}

/// Parsed ZK proof block from capsule
#[derive(Debug, Clone)]
pub struct ZkProofBlock {
    pub program_hash: [u8; 32],
    pub capsule_commitment: [u8; 32],
    /// 32-byte aligned
    pub public_inputs: Vec<u8>,
    /// 192 bytes for Groth16
    pub proof_blob: Vec<u8>,
}

impl ZkProofBlock {
    pub fn is_valid(&self) -> bool {
        self.public_inputs.len() % 32 == 0 && self.proof_blob.len() == GROTH16_PROOF_SIZE
    }
}
