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


use alloc::{vec, vec::Vec};
use crate::crypto::{bigint, vault};
use crate::network::onion::OnionError;

pub struct RealDH;

impl RealDH {
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), OnionError> {
        let p = Self::prime_p();
        let g = bigint::BigUint::from_u64(2);
        let mut x = vec![0u8; 128];
        vault::generate_random_bytes(&mut x).map_err(|_| OnionError::CryptoError)?;
        let x_bn = bigint::BigUint::from_bytes_be(&x) % p.clone();
        let x_bytes = x_bn.to_bytes_be();
        let y = g.mod_pow(&x_bn, &p).ok_or(OnionError::CryptoError)?;
        Ok((Self::pad_1024(&x_bytes), Self::pad_1024(&y.to_bytes_be())))
    }

    pub fn compute_shared(private: &[u8], peer_public: &[u8]) -> Result<Vec<u8>, OnionError> {
        let p = Self::prime_p();
        let x = bigint::BigUint::from_bytes_be(private);
        let y = bigint::BigUint::from_bytes_be(peer_public);
        if y >= p {
            return Err(OnionError::CryptoError);
        }
        let s = y.mod_pow(&x, &p).ok_or(OnionError::CryptoError)?;
        Ok(Self::pad_1024(&s.to_bytes_be()))
    }

    fn prime_p() -> bigint::BigUint {
        bigint::BigUint::from_bytes_be(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
            0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
            0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
            0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
            0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
            0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ])
    }

    fn pad_1024(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() >= 128 {
            return bytes.to_vec();
        }
        let mut out = vec![0u8; 128 - bytes.len()];
        out.extend_from_slice(bytes);
        out
    }
}
