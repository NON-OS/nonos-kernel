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
use crate::crypto::blake3_keyed_hash;

use super::token::MultiSigToken;

pub fn signature_material(token: &MultiSigToken, signer_id: u64) -> [u8; 40] {
    let mut mat = [0u8; 40];
    mat[0..8].copy_from_slice(&signer_id.to_le_bytes());
    mat[8..16].copy_from_slice(&token.owner_module.to_le_bytes());
    mat[16..24].copy_from_slice(&caps_to_bits(&token.permissions).to_le_bytes());
    mat[24..32].copy_from_slice(&token.nonce.to_le_bytes());
    mat[32..40].copy_from_slice(&token.expires_at_ms.unwrap_or(0).to_le_bytes());
    mat
}

pub fn compute_signature(key: &[u8; 32], material: &[u8]) -> [u8; 32] {
    blake3_keyed_hash(key, material)
}
