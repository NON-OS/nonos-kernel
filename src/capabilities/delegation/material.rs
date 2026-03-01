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

use crate::capabilities::bits::caps_to_bits;
use crate::crypto::{blake3_keyed_hash, Blake3Hasher};

use super::types::Delegation;

pub fn delegation_material(d: &Delegation, parent_nonce: u64) -> [u8; 48] {
    let mut mat = [0u8; 48];
    mat[0..8].copy_from_slice(&parent_nonce.to_le_bytes());
    mat[8..16].copy_from_slice(&d.delegator.to_le_bytes());
    mat[16..24].copy_from_slice(&d.delegatee.to_le_bytes());
    mat[24..32].copy_from_slice(&caps_to_bits(&d.capabilities).to_le_bytes());
    mat[32..40].copy_from_slice(&d.expires_at_ms.unwrap_or(0).to_le_bytes());
    mat[40..48].copy_from_slice(&d.parent_nonce.to_le_bytes());
    mat
}

pub fn compute_delegation_signature(key: &[u8; 32], material: &[u8]) -> [u8; 64] {
    let mac1 = blake3_keyed_hash(key, material);
    let mut hasher2 = Blake3Hasher::new_keyed(key);
    hasher2.update(material);
    hasher2.update(b"DELEG");
    let mac2 = hasher2.finalize();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&mac1);
    out[32..].copy_from_slice(&mac2);
    out
}
