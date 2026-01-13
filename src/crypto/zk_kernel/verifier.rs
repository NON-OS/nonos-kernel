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

use spin::Mutex;

use super::schnorr::SchnorrProof;
use super::sigma::SigmaProof;
use super::range::RangeProof;
use super::pedersen::PedersenCommitment;
use super::plonk::PlonkProof;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkResult {
    Valid,
    Invalid,
    MalformedProof,
    UnsupportedProofType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofSystem {
    Schnorr = 1,
    Sigma = 2,
    Range = 3,
    Equality = 4,
    Membership = 5,
    Pedersen = 6,
    Plonk = 7,
}

pub struct KernelZkVerifier {
    pub proofs_verified: u64,
    pub proofs_valid: u64,
    pub proofs_invalid: u64,
}

impl KernelZkVerifier {
    pub const fn new() -> Self {
        Self {
            proofs_verified: 0,
            proofs_valid: 0,
            proofs_invalid: 0,
        }
    }

    pub fn verify_schnorr(
        &mut self,
        commitment: &[u8; 32],
        response: &[u8; 32],
        public_key: &[u8; 32],
    ) -> ZkResult {
        let proof = SchnorrProof {
            commitment: *commitment,
            response: *response,
        };

        self.proofs_verified += 1;

        if proof.verify(public_key) {
            self.proofs_valid += 1;
            ZkResult::Valid
        } else {
            self.proofs_invalid += 1;
            ZkResult::Invalid
        }
    }

    pub fn verify_sigma(
        &mut self,
        a: &[u8; 32],
        e: &[u8; 32],
        z: &[u8; 32],
        proof_type: u8,
        statement: &[u8; 32],
    ) -> ZkResult {
        let proof = SigmaProof {
            a: *a,
            e: *e,
            z: *z,
            proof_type,
        };

        self.proofs_verified += 1;

        if proof.verify(statement) {
            self.proofs_valid += 1;
            ZkResult::Valid
        } else {
            self.proofs_invalid += 1;
            ZkResult::Invalid
        }
    }

    pub fn verify_range(&mut self, proof_bytes: &[u8]) -> ZkResult {
        if proof_bytes.len() < 33 {
            return ZkResult::MalformedProof;
        }

        let bits = proof_bytes[0];
        let expected_len = 1 + 32 + (bits as usize * 32);

        if proof_bytes.len() < expected_len {
            return ZkResult::MalformedProof;
        }

        let mut response = [0u8; 32];
        response.copy_from_slice(&proof_bytes[1..33]);

        let mut bit_commitments = Vec::with_capacity(bits as usize);
        for i in 0..bits as usize {
            let start = 33 + i * 32;
            let mut comm = [0u8; 32];
            comm.copy_from_slice(&proof_bytes[start..start + 32]);
            bit_commitments.push(comm);
        }

        let proof = RangeProof {
            bit_commitments,
            bit_blindings: Vec::new(),
            bit_proofs: Vec::new(),
            response,
            bits,
        };

        self.proofs_verified += 1;

        if proof.verify() {
            self.proofs_valid += 1;
            ZkResult::Valid
        } else {
            self.proofs_invalid += 1;
            ZkResult::Invalid
        }
    }

    pub fn verify_commitment(
        &mut self,
        commitment: &[u8; 32],
        value: &[u8; 32],
        blinding: &[u8; 32],
    ) -> ZkResult {
        let comm = PedersenCommitment { commitment: *commitment };

        self.proofs_verified += 1;

        if comm.verify(value, blinding) {
            self.proofs_valid += 1;
            ZkResult::Valid
        } else {
            self.proofs_invalid += 1;
            ZkResult::Invalid
        }
    }

    pub fn verify_plonk(
        &mut self,
        proof_bytes: &[u8],
        public_inputs: &[[u8; 32]],
    ) -> ZkResult {
        let proof = match PlonkProof::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return ZkResult::MalformedProof,
        };

        self.proofs_verified += 1;

        if proof.verify(public_inputs) {
            self.proofs_valid += 1;
            ZkResult::Valid
        } else {
            self.proofs_invalid += 1;
            ZkResult::Invalid
        }
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (self.proofs_verified, self.proofs_valid, self.proofs_invalid)
    }
}

pub static KERNEL_ZK_VERIFIER: Mutex<KernelZkVerifier> = Mutex::new(KernelZkVerifier::new());
