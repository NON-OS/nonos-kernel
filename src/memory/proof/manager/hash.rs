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

use super::super::types::MemoryRegion;
use super::helpers::blake3_hash;
use super::state::ProofSystem;
use crate::memory::kaslr;
use alloc::vec::Vec;

impl ProofSystem {
    pub(super) fn compute_region_hash(&self, region: &MemoryRegion, salt: u64) -> [u8; 32] {
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&region.start.as_u64().to_le_bytes());
        hash_input.extend_from_slice(&region.end.as_u64().to_le_bytes());
        hash_input.extend_from_slice(&(region.tag as u32).to_le_bytes());
        hash_input.extend_from_slice(&salt.to_le_bytes());
        if let Ok(nonce) = kaslr::boot_nonce() {
            hash_input.extend_from_slice(&nonce.to_le_bytes());
        }
        blake3_hash(&hash_input)
    }

    pub(super) fn derive_access_key(&self, capsule_id: u64, integrity_hash: &[u8; 32]) -> [u8; 32] {
        let mut key_input = Vec::new();
        key_input.extend_from_slice(b"NONOS_CAPSULE_KEY:");
        key_input.extend_from_slice(&capsule_id.to_le_bytes());
        key_input.extend_from_slice(integrity_hash);
        if let Ok(nonce) = kaslr::boot_nonce() {
            key_input.extend_from_slice(&nonce.to_le_bytes());
        }
        blake3_hash(&key_input)
    }
}
