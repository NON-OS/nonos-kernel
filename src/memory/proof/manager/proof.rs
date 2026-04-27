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

use super::super::types::*;
use super::helpers::{blake3_hash, get_timestamp};
use super::state::ProofSystem;
use crate::memory::kaslr;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl ProofSystem {
    pub(super) fn create_proof(&self, addr: u64, size: u64, tag: CapTag) -> u64 {
        let proof_id = self.next_proof_id.fetch_add(1, Ordering::Relaxed);
        let timestamp = get_timestamp();
        let nonce = kaslr::boot_nonce().unwrap_or(0x1337);

        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&addr.to_le_bytes());
        proof_data.extend_from_slice(&size.to_le_bytes());
        proof_data.extend_from_slice(&(tag as u32).to_le_bytes());
        proof_data.extend_from_slice(&timestamp.to_le_bytes());
        proof_data.extend_from_slice(&nonce.to_le_bytes());

        let hash = blake3_hash(&proof_data);
        let proof = MemoryProof { tag, start_addr: addr, size, hash, timestamp, nonce };
        self.proofs.write().insert(proof_id, proof);
        proof_id
    }

    pub(super) fn verify_proof(&self, proof_id: u64) -> Result<bool, &'static str> {
        let proofs = self.proofs.read();
        match proofs.get(&proof_id) {
            Some(proof) => {
                let mut verify_data = Vec::new();
                verify_data.extend_from_slice(&proof.start_addr.to_le_bytes());
                verify_data.extend_from_slice(&proof.size.to_le_bytes());
                verify_data.extend_from_slice(&(proof.tag as u32).to_le_bytes());
                verify_data.extend_from_slice(&proof.timestamp.to_le_bytes());
                verify_data.extend_from_slice(&proof.nonce.to_le_bytes());
                let computed_hash = blake3_hash(&verify_data);
                Ok(computed_hash == proof.hash)
            }
            None => Err("Proof not found"),
        }
    }
}
