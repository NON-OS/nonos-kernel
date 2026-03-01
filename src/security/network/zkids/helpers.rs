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

extern crate alloc;
use alloc::vec::Vec;
use crate::crypto::{hash::blake3_hash, sig::ed25519::Ed25519Signature, fill_random};
use super::types::{Capability, AuthChallenge, ZkId};

pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    blake3_hash(private_key)
}

pub fn secure_random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    bytes
}

pub fn create_proof_statement(challenge: &AuthChallenge, zkid: &ZkId) -> Vec<u8> {
    let mut statement = Vec::new();
    statement.extend_from_slice(&challenge.challenge_id);
    statement.extend_from_slice(&challenge.nonce);
    statement.extend_from_slice(&zkid.id_hash);
    statement.extend_from_slice(&zkid.public_key);
    statement.extend_from_slice(&challenge.timestamp.to_le_bytes());
    for cap in &challenge.required_capabilities {
        statement.extend_from_slice(&capability_to_bytes(cap));
    }
    statement
}

pub fn derive_verification_key(zkid: &ZkId) -> Vec<u8> {
    let mut key_material = Vec::new();
    key_material.extend_from_slice(&zkid.public_key);
    key_material.extend_from_slice(&zkid.id_hash);
    key_material.extend_from_slice(&zkid.created_at.to_le_bytes());
    let mut verification_key = alloc::vec![0u8; 32];
    let derived_key = blake3_hash(&key_material);
    verification_key.copy_from_slice(&derived_key);
    verification_key
}

pub fn capability_to_bytes(capability: &Capability) -> [u8; 32] {
    let cap_str = match capability {
        Capability::SystemAdmin => "system_admin",
        Capability::ProcessManager => "process_manager",
        Capability::MemoryManager => "memory_manager",
        Capability::NetworkAdmin => "network_admin",
        Capability::FileSystem => "filesystem",
        Capability::CryptoOperator => "crypto_operator",
        Capability::ModuleLoader => "module_loader",
        Capability::DebugAccess => "debug_access",
        Capability::TimeCritical => "time_critical",
        Capability::Custom(name) => name,
    };
    blake3_hash(cap_str.as_bytes())
}

pub fn verify_signature(signature: &Ed25519Signature, message: &[u8], public_key: &[u8; 32]) -> bool {
    let sig_bytes = [&signature.R[..], &signature.S[..]].concat();
    crate::crypto::verify_signature(message, &sig_bytes, public_key)
}

pub fn current_timestamp() -> u64 {
    crate::arch::x86_64::time::timer::now_ns() / 1_000_000_000
}
