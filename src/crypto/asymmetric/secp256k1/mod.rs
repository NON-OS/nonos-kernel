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

extern crate alloc;

mod field;
mod scalar;
mod point;
mod ecdsa;

pub use field::FieldElement;
pub use scalar::Scalar;
pub use point::{AffinePoint, ProjectivePoint};
pub use ecdsa::{generate_keypair, public_key_from_secret, sign, verify, recover_public_key, eth_address};
pub use ecdsa::sign as sign_recoverable;

pub type SecretKey = [u8; 32];
pub type PublicKey = [u8; 65];
pub type CompressedPublicKey = [u8; 33];
pub type Signature = [u8; 64];

#[derive(Debug, Clone, Copy)]
pub struct RecoverableSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

impl RecoverableSignature {
    pub fn from_bytes(bytes: &[u8; 65]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        Self {
            r,
            s,
            recovery_id: bytes[64],
        }
    }

    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.recovery_id;
        bytes
    }
}

use crate::crypto::{CryptoError, CryptoResult};

/// Multiply a point by a scalar (ECDH shared secret computation).
pub fn multiply_point(point: &PublicKey, scalar: &SecretKey) -> CryptoResult<[u8; 65]> {
    let affine = AffinePoint::from_uncompressed(point)
        .ok_or(CryptoError::InvalidInput)?;
    let s = Scalar::from_bytes(scalar)
        .ok_or(CryptoError::InvalidInput)?;

    let result = affine.to_projective().mul(&s).to_affine();
    if result.infinity {
        return Err(CryptoError::InvalidInput);
    }

    Ok(result.to_uncompressed())
}

/// Add two elliptic curve points.
pub fn point_add(a: &PublicKey, b: &PublicKey) -> CryptoResult<PublicKey> {
    let a_affine = AffinePoint::from_uncompressed(a)
        .ok_or(CryptoError::InvalidInput)?;
    let b_affine = AffinePoint::from_uncompressed(b)
        .ok_or(CryptoError::InvalidInput)?;

    let result = a_affine.to_projective().add(&b_affine.to_projective()).to_affine();
    if result.infinity {
        return Err(CryptoError::InvalidInput);
    }

    Ok(result.to_uncompressed())
}

/// Multiply a point by a scalar (alias for multiply_point with generator).
pub fn scalar_multiply(point: &[u8; 65], scalar: &[u8; 32]) -> CryptoResult<[u8; 65]> {
    multiply_point(point, scalar)
}

/// Decompress a compressed public key (33 bytes) to uncompressed (65 bytes).
pub fn decompress_pubkey(compressed: &[u8]) -> CryptoResult<PublicKey> {
    if compressed.len() != 33 {
        return Err(CryptoError::InvalidLength);
    }

    let compressed_arr: &[u8; 33] = compressed.try_into()
        .map_err(|_| CryptoError::InvalidLength)?;

    let affine = AffinePoint::from_compressed(compressed_arr)
        .ok_or(CryptoError::InvalidInput)?;

    Ok(affine.to_uncompressed())
}
