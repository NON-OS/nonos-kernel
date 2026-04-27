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

use super::{AffinePoint, PublicKey, Scalar, Signature};

/// ECDSA verification over P-384.
/// `pk`: 97-byte uncompressed public key (0x04 || x || y)
/// `message_hash`: 48-byte SHA-384 hash of the message
/// `sig`: 96-byte raw signature (r || s, each 48 bytes big-endian)
pub fn verify(pk: &PublicKey, message_hash: &[u8; 48], sig: &Signature) -> bool {
    let mut valid: u64 = 1;

    let point = match AffinePoint::from_uncompressed(pk) {
        Some(p) => p,
        None => {
            valid = 0;
            AffinePoint::identity()
        }
    };

    let r_bytes: [u8; 48] = match sig[0..48].try_into() {
        Ok(b) => b,
        Err(_) => {
            valid = 0;
            [0u8; 48]
        }
    };
    let (r, r_valid) = match Scalar::from_bytes(&r_bytes) {
        Some(r) if !r.is_zero() => (r, 1u64),
        Some(_) => (Scalar::ONE, 0u64),
        None => (Scalar::ONE, 0u64),
    };
    valid &= r_valid;

    let s_bytes: [u8; 48] = match sig[48..96].try_into() {
        Ok(b) => b,
        Err(_) => {
            valid = 0;
            [0u8; 48]
        }
    };
    let (s, s_valid) = match Scalar::from_bytes(&s_bytes) {
        Some(s) if !s.is_zero() => (s, 1u64),
        Some(_) => (Scalar::ONE, 0u64),
        None => (Scalar::ONE, 0u64),
    };
    valid &= s_valid;

    let z = Scalar::from_bytes_reduce(message_hash);

    let (s_inv, inv_valid) = match s.invert() {
        Some(inv) => (inv, 1u64),
        None => (Scalar::ONE, 0u64),
    };
    valid &= inv_valid;

    let u1 = z.mul(&s_inv);
    let u2 = r.mul(&s_inv);

    let g = AffinePoint::generator().to_projective();
    let q = point.to_projective();
    let r_prime = g.mul(&u1).add(&q.mul(&u2)).to_affine();

    let not_infinity = if r_prime.infinity { 0u64 } else { 1u64 };
    valid &= not_infinity;

    let computed_r = Scalar::from_bytes_reduce(&r_prime.x.to_bytes());

    let r_matches = if computed_r.ct_eq(&r) { 1u64 } else { 0u64 };
    valid &= r_matches;

    valid == 1
}
