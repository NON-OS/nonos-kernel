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

//! P-256 Elliptic Curve Diffie-Hellman (ECDH) key agreement.
//!
//! Implements SEC 1 §3.3.1 (ECDH Primitive) using the existing constant-time
//! P-256 scalar multiplication from `point::ProjectivePoint::mul`.

use super::{AffinePoint, PublicKey, Scalar, SecretKey};

/// Generate an ephemeral P-256 keypair for ECDH.
///
/// Returns `(secret_key [32 bytes], public_key [65 bytes uncompressed])`.
/// The public key format is `0x04 || x || y` as required by TLS key_share.
pub fn p256_ecdh_keypair() -> (SecretKey, PublicKey) {
    let mut sk = [0u8; 32];
    crate::crypto::rng::fill_random_bytes(&mut sk);

    loop {
        if let Some(scalar) = Scalar::from_bytes(&sk) {
            if !scalar.is_zero() {
                let point = AffinePoint::generator().to_projective().mul(&scalar).to_affine();
                if !point.infinity {
                    return (sk, point.to_uncompressed());
                }
            }
        }
        crate::crypto::rng::fill_random_bytes(&mut sk);
    }
}

/// Perform P-256 ECDH: compute shared secret from our secret key and peer's
/// uncompressed public key.
///
/// Returns the x-coordinate of `sk * peer_pub` as a 32-byte shared secret,
/// per SEC 1 §3.3.1 and RFC 8446 §4.2.8.2.
///
/// Validates that:
/// - The peer public key is a valid point on the P-256 curve
/// - The peer public key is not the point at infinity
/// - The resulting shared secret point is not the point at infinity
pub fn p256_ecdh(sk: &[u8; 32], peer_pub: &[u8; 65]) -> Option<[u8; 32]> {
    let scalar = Scalar::from_bytes(sk)?;
    if scalar.is_zero() {
        return None;
    }

    // AffinePoint::from_uncompressed validates the point is on the curve
    let peer_point = AffinePoint::from_uncompressed(peer_pub)?;
    if peer_point.infinity {
        return None;
    }

    let shared = peer_point.to_projective().mul(&scalar).to_affine();
    if shared.infinity {
        return None;
    }

    Some(shared.x.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_round_trip() {
        let (sk_a, pk_a) = p256_ecdh_keypair();
        let (sk_b, pk_b) = p256_ecdh_keypair();

        let shared_ab = p256_ecdh(&sk_a, &pk_b).expect("ECDH A->B failed");
        let shared_ba = p256_ecdh(&sk_b, &pk_a).expect("ECDH B->A failed");

        assert_eq!(shared_ab, shared_ba, "shared secrets must match");
        assert_ne!(shared_ab, [0u8; 32], "shared secret must not be zero");
    }

    #[test]
    fn test_ecdh_keypair_valid() {
        let (sk, pk) = p256_ecdh_keypair();
        assert_eq!(pk[0], 0x04, "public key must be uncompressed format");
        assert_eq!(pk.len(), 65);
        assert_ne!(sk, [0u8; 32], "secret key must not be zero");
        // Verify the public key is on the curve by parsing it
        let point = AffinePoint::from_uncompressed(&pk);
        assert!(point.is_some(), "public key must be a valid curve point");
    }

    #[test]
    fn test_ecdh_rejects_identity() {
        let (sk, _) = p256_ecdh_keypair();
        // Identity point: 0x04 followed by zeros is not on the curve,
        // so from_uncompressed will reject it
        let bad_pub = [0u8; 65];
        assert!(p256_ecdh(&sk, &bad_pub).is_none());
    }

    #[test]
    fn test_ecdh_rejects_invalid_point() {
        let (sk, _) = p256_ecdh_keypair();
        let mut bad_pub = [0u8; 65];
        bad_pub[0] = 0x04;
        bad_pub[1] = 0x01; // (1, 0) is not on the P-256 curve
        assert!(p256_ecdh(&sk, &bad_pub).is_none());
    }

    #[test]
    fn test_ecdh_rejects_zero_scalar() {
        let zero_sk = [0u8; 32];
        let (_, pk) = p256_ecdh_keypair();
        assert!(p256_ecdh(&zero_sk, &pk).is_none());
    }

    // NIST SP 800-56A test vector (CAVP ECC CDH)
    // P-256 curve, count 0
    #[test]
    fn test_ecdh_nist_vector() {
        // Private key d (party A)
        let d_a: [u8; 32] = [
            0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, 0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e,
            0xea, 0xe0, 0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, 0xd8, 0x0b, 0xad, 0xb6,
            0x2b, 0xc1, 0xa5, 0x34,
        ];

        // Public key Q (party B) — uncompressed
        let q_b: [u8; 65] = {
            let mut pk = [0u8; 65];
            pk[0] = 0x04;
            // x-coordinate
            let x: [u8; 32] = [
                0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, 0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64,
                0x0d, 0xb9, 0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, 0x2c, 0xe7, 0xcc, 0x83,
                0x88, 0x33, 0xd2, 0x87,
            ];
            let y: [u8; 32] = [
                0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, 0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51,
                0xdc, 0xc5, 0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, 0x44, 0x17, 0x82, 0xca,
                0xb8, 0x5f, 0xa4, 0xac,
            ];
            pk[1..33].copy_from_slice(&x);
            pk[33..65].copy_from_slice(&y);
            pk
        };

        // Expected shared secret (x-coordinate of d_a * Q_b)
        let expected: [u8; 32] = [
            0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, 0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd,
            0x2d, 0x25, 0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, 0x04, 0x0d, 0xd7, 0x77,
            0x89, 0x97, 0xbd, 0x7b,
        ];

        let result = p256_ecdh(&d_a, &q_b).expect("NIST ECDH vector failed");
        assert_eq!(result, expected, "NIST P-256 ECDH test vector mismatch");
    }
}
