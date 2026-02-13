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
use spin::Mutex;

pub const DS_ATTESTATION: &str = "NONOS:ATTESTATION:v1";
pub const MAX_PCRS: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PcrIndex {
    Firmware = 0,
    FirmwareConfig = 1,
    OptionRom = 2,
    BootConfig = 3,
    Mbr = 4,
    GptPartition = 5,
    VendorSpecific = 6,
    SecureBootState = 7,
    Bootloader = 8,
    Kernel = 9,
    ZkProof = 10,
    BootAudit = 11,
}

#[derive(Clone, Copy)]
pub struct PcrValue {
    pub index: u8,
    pub value: [u8; 32],
    pub extended: bool,
}

impl PcrValue {
    pub const fn empty(index: u8) -> Self {
        Self {
            index,
            value: [0u8; 32],
            extended: false,
        }
    }

    pub fn extend(&mut self, data: &[u8]) {
        let mut hasher = blake3::Hasher::new_derive_key(DS_ATTESTATION);
        hasher.update(&self.value);
        hasher.update(data);
        self.value = *hasher.finalize().as_bytes();
        self.extended = true;
    }

    pub fn extend_hash(&mut self, hash: &[u8; 32]) {
        let mut hasher = blake3::Hasher::new_derive_key(DS_ATTESTATION);
        hasher.update(&self.value);
        hasher.update(hash);
        self.value = *hasher.finalize().as_bytes();
        self.extended = true;
    }
}

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
                PcrValue::empty(0),
                PcrValue::empty(1),
                PcrValue::empty(2),
                PcrValue::empty(3),
                PcrValue::empty(4),
                PcrValue::empty(5),
                PcrValue::empty(6),
                PcrValue::empty(7),
                PcrValue::empty(8),
                PcrValue::empty(9),
                PcrValue::empty(10),
                PcrValue::empty(11),
                PcrValue::empty(12),
                PcrValue::empty(13),
                PcrValue::empty(14),
                PcrValue::empty(15),
                PcrValue::empty(16),
                PcrValue::empty(17),
                PcrValue::empty(18),
                PcrValue::empty(19),
                PcrValue::empty(20),
                PcrValue::empty(21),
                PcrValue::empty(22),
                PcrValue::empty(23),
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

    pub fn set_zk_verified(
        &mut self,
        verified: bool,
        program_hash: [u8; 32],
        commitment: [u8; 32],
    ) {
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

pub static ATTESTATION_STATE: Mutex<AttestationState> = Mutex::new(AttestationState::new());

pub fn init_attestation() {
    let mut state = ATTESTATION_STATE.lock();
    state.init();
}

pub fn extend_pcr(index: PcrIndex, data: &[u8]) {
    let mut state = ATTESTATION_STATE.lock();
    state.extend_pcr(index, data);
}

pub fn extend_pcr_hash(index: PcrIndex, hash: &[u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.extend_pcr_hash(index, hash);
}

pub fn set_kernel_measurement(hash: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_kernel_hash(hash);
}

pub fn set_bootloader_measurement(hash: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_bootloader_hash(hash);
}

pub fn set_zk_attestation(verified: bool, program_hash: [u8; 32], commitment: [u8; 32]) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_zk_verified(verified, program_hash, commitment);
}

pub fn set_signature_attestation(verified: bool) {
    let mut state = ATTESTATION_STATE.lock();
    state.set_signature_verified(verified);
}

pub fn generate_attestation_quote(nonce: [u8; 32], timestamp: u64) -> AttestationQuote {
    let state = ATTESTATION_STATE.lock();
    state.generate_quote(nonce, timestamp)
}

pub fn get_boot_measurement() -> [u8; 32] {
    let state = ATTESTATION_STATE.lock();
    state.compute_composite_hash()
}

pub fn generate_signed_quote_with_aik(
    nonce: [u8; 32],
    timestamp: u64,
    aik: &ed25519_dalek::SigningKey,
) -> AttestationQuote {
    let state = ATTESTATION_STATE.lock();
    state.generate_signed_quote(nonce, timestamp, aik)
}

pub fn verify_attestation_quote(
    quote: &AttestationQuote,
    attestation_public_key: &[u8; 32],
) -> bool {
    quote.verify(attestation_public_key)
}
