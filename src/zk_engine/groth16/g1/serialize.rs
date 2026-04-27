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

use super::super::field::FieldElement;
use super::types::{G1Affine, G1Point};
use crate::zk_engine::ZKError;

impl G1Point {
    pub fn to_affine_coords(&self) -> Option<(FieldElement, FieldElement)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.inverse()?;
        Some((self.x.mul(&z_inv), self.y.mul(&z_inv)))
    }

    pub fn to_affine(&self) -> G1Affine {
        if self.is_infinity() {
            return G1Affine { x: FieldElement::zero(), y: FieldElement::zero() };
        }
        let z_inv = self.z.invert().unwrap_or(FieldElement::zero());
        let z_inv2 = z_inv.mul(&z_inv);
        let z_inv3 = z_inv2.mul(&z_inv);
        G1Affine { x: self.x.mul(&z_inv2), y: self.y.mul(&z_inv3) }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        if let Some((x, y)) = self.to_affine_coords() {
            let mut bytes = [0u8; 32];
            let x_mont = x.from_montgomery();
            for i in 0..4 {
                let lb = x_mont.limbs[i].to_le_bytes();
                bytes[i * 8..(i + 1) * 8].copy_from_slice(&lb);
            }
            let y_mont = y.from_montgomery();
            if y_mont.limbs[0] & 1 == 1 {
                bytes[31] |= 0x80;
            }
            bytes
        } else {
            [0u8; 32]
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZKError> {
        if bytes.len() < 32 {
            return Err(ZKError::InvalidProof);
        }
        if bytes.iter().all(|&b| b == 0) {
            return Ok(G1Point::infinity());
        }
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[0..32]);
        let y_bit = (x_bytes[31] & 0x80) != 0;
        x_bytes[31] &= 0x7f;
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes([
                x_bytes[i * 8],
                x_bytes[i * 8 + 1],
                x_bytes[i * 8 + 2],
                x_bytes[i * 8 + 3],
                x_bytes[i * 8 + 4],
                x_bytes[i * 8 + 5],
                x_bytes[i * 8 + 6],
                x_bytes[i * 8 + 7],
            ]);
        }
        let x = FieldElement { limbs }.to_montgomery();
        let y_squared = x.square().mul(&x).add(&FieldElement::from_u64(3));
        let y = y_squared.sqrt().ok_or(ZKError::InvalidProof)?;
        let y_final =
            if (y.from_montgomery().limbs[0] & 1) == (y_bit as u64) { y } else { y.neg() };
        let point = G1Point { x, y: y_final, z: FieldElement::one() };
        if point.is_on_curve() {
            Ok(point)
        } else {
            Err(ZKError::InvalidProof)
        }
    }
}
