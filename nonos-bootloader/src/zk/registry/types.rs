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
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CircuitPermission {
    BootAuthority = 1 << 0,
    UpdateAuthority = 1 << 1,
    RecoveryKey = 1 << 2,
    CommunityKey = 1 << 3,
    UserCircuit = 1 << 4,
    Attestation = 1 << 5,
    CircuitAdmin = 1 << 6,
    NetworkAccess = 1 << 7,
    FilesystemAccess = 1 << 8,
    HardwareAccess = 1 << 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitCategory {
    Core,
    System,
    Community,
    User,
}

#[derive(Debug, Clone)]
pub struct CircuitEntry {
    pub program_hash: [u8; 32],
    pub vk_bytes: &'static [u8],
    pub name: &'static str,
    pub version: &'static str,
    pub permissions: u32,
    pub category: CircuitCategory,
    pub signature: Option<&'static [u8; 64]>,
    pub signer: Option<&'static [u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct DynamicCircuitEntry {
    pub program_hash: [u8; 32],
    pub vk_bytes: Vec<u8>,
    pub name: Vec<u8>,
    pub permissions: u32,
    pub category: CircuitCategory,
    pub loaded_at: u64,
}

#[repr(C)]
pub struct CircuitSectionHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub count: u32,
    pub size: u32,
    pub signature: [u8; 64],
    pub signer: [u8; 32],
}

#[repr(C)]
pub struct CircuitSectionEntry {
    pub program_hash: [u8; 32],
    pub permissions: u32,
    pub category: u8,
    pub name_len: u8,
    pub version_len: u8,
    pub _reserved: u8,
    pub vk_offset: u32,
    pub vk_len: u32,
}

pub const CIRCUIT_SECTION_MAGIC: [u8; 4] = [b'N', 0xC3, b'Z', b'K'];
pub const DS_CIRCUIT_SIGN: &str = "NONOS:CIRCUIT:SIGN:v1";

impl CircuitEntry {
    pub fn compute_signing_data(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(DS_CIRCUIT_SIGN);
        h.update(&self.program_hash);
        h.update(self.vk_bytes);
        h.update(self.name.as_bytes());
        h.update(self.version.as_bytes());
        h.update(&self.permissions.to_le_bytes());
        h.update(&[self.category as u8]);
        *h.finalize().as_bytes()
    }

    pub fn has_valid_signature(&self) -> bool {
        match (self.signature, self.signer) {
            (Some(sig), Some(pubkey)) => {
                let msg = self.compute_signing_data();
                verify_circuit_signature(&msg, sig, pubkey)
            }
            _ => false,
        }
    }

    pub fn is_core_signed(&self) -> bool {
        self.category == CircuitCategory::Core && self.has_valid_signature()
    }
}

fn verify_circuit_signature(msg: &[u8; 32], sig: &[u8; 64], pubkey: &[u8; 32]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}
