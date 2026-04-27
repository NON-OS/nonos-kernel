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

use crate::crypto::curve25519;

pub fn x25519_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    curve25519::x25519(scalar, point)
}

pub fn x25519_base_point_mult(scalar: &[u8; 32]) -> [u8; 32] {
    curve25519::x25519_base(scalar)
}

pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    let _ = crate::crypto::random::fill_bytes(&mut secret);
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    let public = x25519_base_point_mult(&secret);
    (secret, public)
}

pub fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

pub fn is_valid_point(point: &[u8; 32]) -> bool {
    let mut all_zero = true;
    for b in point {
        if *b != 0 {
            all_zero = false;
            break;
        }
    }
    !all_zero
}
