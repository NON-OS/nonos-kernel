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

use super::pcr::{PcrIndex, PcrValue, DS_ATTESTATION, MAX_PCRS};
use super::quote::AttestationQuote;

pub struct AttestationState {
    pcrs: [PcrValue; MAX_PCRS],
    kernel_hash: [u8; 32],
    bootloader_hash: [u8; 32],
    zk_verified: bool,
    sig_verified: bool,
    program_hash: [u8; 32],
    capsule_commitment: [u8; 32],
    initialized: bool,
}

impl AttestationState {
    pub const fn new() -> Self {
        Self {
            pcrs: [
                PcrValue::empty(0), PcrValue::empty(1), PcrValue::empty(2), PcrValue::empty(3),
                PcrValue::empty(4), PcrValue::empty(5), PcrValue::empty(6), PcrValue::empty(7),
                PcrValue::empty(8), PcrValue::empty(9), PcrValue::empty(10), PcrValue::empty(11),
                PcrValue::empty(12), PcrValue::empty(13), PcrValue::empty(14), PcrValue::empty(15),
                PcrValue::empty(16), PcrValue::empty(17), PcrValue::empty(18), PcrValue::empty(19),
                PcrValue::empty(20), PcrValue::empty(21), PcrValue::empty(22), PcrValue::empty(23),
            ],
            kernel_hash: [0u8; 32],
            bootloader_hash: [0u8; 32],
            zk_verified: false,
            sig_verified: false,
            program_hash: [0u8; 32],
            capsule_commitment: [0u8; 32],
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        self.initialized = true;
    }

    pub fn extend_pcr(&mut self, index: PcrIndex, data: &[u8]) {
        let idx = index as usize;
        if idx < MAX_PCRS {
            self.pcrs[idx].extend(data);
        }
    }

    pub fn extend_pcr_hash(&mut self, index: PcrIndex, hash: &[u8; 32]) {
        let idx = index as usize;
        if idx < MAX_PCRS {
            self.pcrs[idx].extend_hash(hash);
        }
    }

    pub fn set_kernel_hash(&mut self, hash: [u8; 32]) {
        self.kernel_hash = hash;
        self.extend_pcr_hash(PcrIndex::Kernel, &hash);
    }

    pub fn set_bootloader_hash(&mut self, hash: [u8; 32]) {
        self.bootloader_hash = hash;
        self.extend_pcr_hash(PcrIndex::Bootloader, &hash);
    }

    pub fn set_zk_verified(&mut self, verified: bool, program_hash: [u8; 32], commitment: [u8; 32]) {
        self.zk_verified = verified;
        self.program_hash = program_hash;
        self.capsule_commitment = commitment;
        self.extend_pcr_hash(PcrIndex::ZkProof, &program_hash);
    }

    pub fn set_signature_verified(&mut self, verified: bool) {
        self.sig_verified = verified;
    }

    pub fn get_pcr(&self, index: PcrIndex) -> &PcrValue {
        &self.pcrs[index as usize]
    }

    pub fn generate_quote(&self, nonce: [u8; 32], timestamp: u64) -> AttestationQuote {
        let mut quote = AttestationQuote::new(nonce, timestamp);

        quote.add_pcr(PcrIndex::SecureBootState as u8, self.pcrs[7].value);
        quote.add_pcr(PcrIndex::Bootloader as u8, self.pcrs[8].value);
        quote.add_pcr(PcrIndex::Kernel as u8, self.pcrs[9].value);
        quote.add_pcr(PcrIndex::ZkProof as u8, self.pcrs[10].value);
        quote.add_pcr(PcrIndex::BootAudit as u8, self.pcrs[11].value);

        quote.kernel_hash = self.kernel_hash;
        quote.bootloader_hash = self.bootloader_hash;
        quote.zk_proof_verified = self.zk_verified;
        quote.signature_verified = self.sig_verified;
        quote.program_hash = self.program_hash;
        quote.capsule_commitment = self.capsule_commitment;

        quote
    }

    pub fn generate_signed_quote(
        &self,
        nonce: [u8; 32],
        timestamp: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> AttestationQuote {
        use ed25519_dalek::Signer;

        let mut quote = self.generate_quote(nonce, timestamp);
        let quote_hash = quote.compute_quote_hash();
        let signature = signing_key.sign(&quote_hash);
        quote.quote_signature = signature.to_bytes();
        quote
    }

    pub fn compute_composite_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DS_ATTESTATION);

        for pcr in &self.pcrs {
            if pcr.extended {
                hasher.update(&[pcr.index]);
                hasher.update(&pcr.value);
            }
        }

        *hasher.finalize().as_bytes()
    }
}
