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

pub fn token_material(owner: u64, bits: u64, exp: u64, nonce: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&owner.to_le_bytes());
    out[8..16].copy_from_slice(&bits.to_le_bytes());
    out[16..24].copy_from_slice(&exp.to_le_bytes());
    out[24..32].copy_from_slice(&nonce.to_le_bytes());
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
