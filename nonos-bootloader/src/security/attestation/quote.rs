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
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::pcr::DS_ATTESTATION;

#[derive(Clone)]
pub struct AttestationQuote {
    pub pcr_values: [(u8, [u8; 32]); 12],
    pub pcr_count: usize,
    pub kernel_hash: [u8; 32],
    pub bootloader_hash: [u8; 32],
    pub zk_proof_verified: bool,
    pub signature_verified: bool,
    pub program_hash: [u8; 32],
    pub capsule_commitment: [u8; 32],
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub quote_signature: [u8; 64],
}

impl AttestationQuote {
    pub fn new(nonce: [u8; 32], timestamp: u64) -> Self {
        Self {
            pcr_values: [(0, [0u8; 32]); 12],
            pcr_count: 0,
            kernel_hash: [0u8; 32],
            bootloader_hash: [0u8; 32],
            zk_proof_verified: false,
            signature_verified: false,
            program_hash: [0u8; 32],
            capsule_commitment: [0u8; 32],
            nonce,
            timestamp,
            quote_signature: [0u8; 64],
        }
    }

    pub fn add_pcr(&mut self, index: u8, value: [u8; 32]) {
        if self.pcr_count < 12 {
            self.pcr_values[self.pcr_count] = (index, value);
            self.pcr_count += 1;
        }
    }

    pub fn compute_quote_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DS_ATTESTATION);

        hasher.update(&self.nonce);
        hasher.update(&self.timestamp.to_le_bytes());

        for i in 0..self.pcr_count {
            hasher.update(&[self.pcr_values[i].0]);
            hasher.update(&self.pcr_values[i].1);
        }

        hasher.update(&self.kernel_hash);
        hasher.update(&self.bootloader_hash);
        hasher.update(&[self.zk_proof_verified as u8]);
        hasher.update(&[self.signature_verified as u8]);
        hasher.update(&self.program_hash);
        hasher.update(&self.capsule_commitment);

        *hasher.finalize().as_bytes()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.push(self.pcr_count as u8);

        for i in 0..self.pcr_count {
            buf.push(self.pcr_values[i].0);
            buf.extend_from_slice(&self.pcr_values[i].1);
        }

        buf.extend_from_slice(&self.kernel_hash);
        buf.extend_from_slice(&self.bootloader_hash);
        buf.push(self.zk_proof_verified as u8);
        buf.push(self.signature_verified as u8);
        buf.extend_from_slice(&self.program_hash);
        buf.extend_from_slice(&self.capsule_commitment);
        buf.extend_from_slice(&self.quote_signature);

        buf
    }

    pub fn verify(&self, attestation_public_key: &[u8; 32]) -> bool {
        let quote_hash = self.compute_quote_hash();

        let vk = match VerifyingKey::from_bytes(attestation_public_key) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let sig = Signature::from_bytes(&self.quote_signature);

        vk.verify(&quote_hash, &sig).is_ok()
    }

    pub fn has_valid_measurements(&self) -> bool {
        self.zk_proof_verified && self.signature_verified
    }
}
