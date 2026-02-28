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
use super::keygen::{PrivateKey, PublicKey};
use super::scalar::{sc_reduce, sc_mul, sc_add};

pub type Signature = [u8; 64];

pub fn sign(private_key: &PrivateKey, public_key: &PublicKey, message: &[u8]) -> Signature {
    let h = sha512(private_key);

    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    let prefix = &h[32..64];

    let mut r_input = alloc::vec::Vec::with_capacity(32 + message.len());
    r_input.extend_from_slice(prefix);
    r_input.extend_from_slice(message);
    let r_hash = sha512(&r_input);
    let r = sc_reduce(&r_hash);

    let r_point = BASEPOINT.scalar_mul(&r);
    let r_compressed = r_point.compress();

    let mut k_input = alloc::vec::Vec::with_capacity(32 + 32 + message.len());
    k_input.extend_from_slice(&r_compressed);
    k_input.extend_from_slice(public_key);
    k_input.extend_from_slice(message);
    let k_hash = sha512(&k_input);
    let k = sc_reduce(&k_hash);

    let ks = sc_mul(&k, &s);
    let sig_s = sc_add(&r, &ks);

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_compressed);
    signature[32..].copy_from_slice(&sig_s);

    signature
}
