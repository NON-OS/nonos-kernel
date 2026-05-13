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

use super::types::CapabilityToken;

// 8+8+8+8 legacy (owner/bits/exp/nonce) +
// 8+4+4+32+16+8+1 new authority material = 105 bytes, padded to 128.
pub(super) const TOKEN_MATERIAL_SIZE: usize = 128;

pub fn token_material(tok: &CapabilityToken, bits: u64) -> [u8; TOKEN_MATERIAL_SIZE] {
    let mut out = [0u8; TOKEN_MATERIAL_SIZE];
    out[0..8].copy_from_slice(&tok.owner_module.to_le_bytes());
    out[8..16].copy_from_slice(&bits.to_le_bytes());
    out[16..24].copy_from_slice(&tok.expires_at_ms.unwrap_or(0).to_le_bytes());
    out[24..32].copy_from_slice(&tok.nonce.to_le_bytes());
    out[32..40].copy_from_slice(&tok.token_id.to_le_bytes());
    out[40..44].copy_from_slice(&tok.subject_capsule_id.to_le_bytes());
    out[44..48].copy_from_slice(&tok.subject_asid.to_le_bytes());
    out[48..80].copy_from_slice(&tok.subject_measurement);
    out[80..96].copy_from_slice(&tok.boot_session_nonce);
    out[96..104].copy_from_slice(&tok.revocation_epoch.to_le_bytes());
    out[104] = tok.delegation_depth;
    out
}

pub fn mac64(key: &[u8; 32], mat: &[u8]) -> [u8; 64] {
    let mac1 = blake3_keyed_hash(key, mat);
    let mut ctx2 = Blake3Hasher::new_keyed(key);
    ctx2.update(mat);
    ctx2.update(b"CAP2");
    let mac2 = ctx2.finalize();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&mac1);
    out[32..].copy_from_slice(&mac2);
    out
}
