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

use crate::crypto::{blake3_keyed_hash, Blake3Hasher};

use super::quota::ResourceQuota;

pub fn token_material(owner: u64, quota: &ResourceQuota, nonce: u64) -> [u8; 40] {
    let mut mat = [0u8; 40];
    mat[0..8].copy_from_slice(&owner.to_le_bytes());
    mat[8..16].copy_from_slice(&quota.bytes.to_le_bytes());
    mat[16..24].copy_from_slice(&quota.ops.to_le_bytes());
    mat[24..32].copy_from_slice(&quota.expires_at_ms.unwrap_or(0).to_le_bytes());
    mat[32..40].copy_from_slice(&nonce.to_le_bytes());
    mat
}

pub fn compute_signature(key: &[u8; 32], material: &[u8]) -> [u8; 64] {
    let mac1 = blake3_keyed_hash(key, material);
    let mut hasher2 = Blake3Hasher::new_keyed(key);
    hasher2.update(material);
    hasher2.update(b"RSRC");
    let mac2 = hasher2.finalize();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&mac1);
    out[32..].copy_from_slice(&mac2);
    out
}
