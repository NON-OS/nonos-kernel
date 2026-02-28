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

use crate::crypto::entropy::get_entropy;
use crate::crypto::sha512::sha512;
use super::constants::BASEPOINT;

pub type PrivateKey = [u8; 32];
pub type PublicKey = [u8; 32];

pub fn keypair_from_seed(seed: &[u8; 32]) -> (PublicKey, PrivateKey) {
    let h = sha512(seed);

    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;

    let public_point = BASEPOINT.scalar_mul(&s);
    let public = public_point.compress();

    (public, *seed)
}

pub fn generate_keypair() -> (PublicKey, PrivateKey) {
    let entropy = get_entropy(32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&entropy);
    keypair_from_seed(&seed)
}
