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

use crate::crypto::sha512::sha512;
use super::constants::BASEPOINT;
use super::keygen::PublicKey;
use super::point::EdwardsPoint;
use super::sign::Signature;
use super::scalar::{sc_is_invalid, sc_reduce};

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    if sc_is_invalid(&s_bytes) {
        return false;
    }

    let r_compressed = &signature[..32];

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(r_compressed);
    let r_point = match EdwardsPoint::decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    let a_point = match EdwardsPoint::decompress(public_key) {
        Some(p) => p,
        None => return false,
    };

    let mut k_input = alloc::vec::Vec::with_capacity(32 + 32 + message.len());
    k_input.extend_from_slice(r_compressed);
    k_input.extend_from_slice(public_key);
    k_input.extend_from_slice(message);
    let k_hash = sha512(&k_input);
    let k = sc_reduce(&k_hash);

    let sb = BASEPOINT.scalar_mul(&s_bytes);
    let ka = a_point.scalar_mul(&k);
    let rhs = r_point.add(&ka);

    sb.compress() == rhs.compress()
}
