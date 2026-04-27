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

use super::field_element::G2FieldElement;
use super::point::G2Point;
use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl G2Point {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        if let Some((x, _y)) = self.to_affine_coords() {
            let x0_mont = x.c0.from_montgomery();
            let x1_mont = x.c1.from_montgomery();
            for i in 0..4 {
                bytes[i * 8..(i + 1) * 8].copy_from_slice(&x0_mont.limbs[i].to_le_bytes());
            }
            for i in 0..4 {
                bytes[(i + 4) * 8..(i + 5) * 8].copy_from_slice(&x1_mont.limbs[i].to_le_bytes());
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZKError> {
        if bytes.len() < 64 {
            return Err(ZKError::InvalidProof);
        }
        let mut c0_limbs = [0u64; 4];
        let mut c1_limbs = [0u64; 4];
        for i in 0..4 {
            c0_limbs[i] = u64::from_le_bytes([
                bytes[i * 8],
                bytes[i * 8 + 1],
                bytes[i * 8 + 2],
                bytes[i * 8 + 3],
                bytes[i * 8 + 4],
                bytes[i * 8 + 5],
                bytes[i * 8 + 6],
                bytes[i * 8 + 7],
            ]);
            c1_limbs[i] = u64::from_le_bytes([
                bytes[(i + 4) * 8],
                bytes[(i + 4) * 8 + 1],
                bytes[(i + 4) * 8 + 2],
                bytes[(i + 4) * 8 + 3],
                bytes[(i + 4) * 8 + 4],
                bytes[(i + 4) * 8 + 5],
                bytes[(i + 4) * 8 + 6],
                bytes[(i + 4) * 8 + 7],
            ]);
        }
        let x = G2FieldElement {
            c0: FieldElement { limbs: c0_limbs }.to_montgomery(),
            c1: FieldElement { limbs: c1_limbs }.to_montgomery(),
        };
        Ok(G2Point { x, y: G2FieldElement::one(), z: G2FieldElement::one() })
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 128 {
            return Err(ZKError::InvalidFormat);
        }
        if data.iter().all(|&b| b == 0) {
            return Ok(G2Point::identity());
        }
        let x = Self::parse_fp2(&data[0..64])?;
        let y = Self::parse_fp2(&data[64..128])?;
        Ok(G2Point { x, y, z: G2FieldElement::one() })
    }

    fn parse_fp2(data: &[u8]) -> Result<G2FieldElement, ZKError> {
        let c0 = FieldElement::from_bytes(&data[0..32])?;
        let c1 = FieldElement::from_bytes(&data[32..64])?;
        Ok(G2FieldElement { c0, c1 })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(128);
        if let Some((x, y)) = self.to_affine_coords() {
            let x0_mont = x.c0.from_montgomery();
            let x1_mont = x.c1.from_montgomery();
            for limb in x0_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }
            for limb in x1_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }
            let y0_mont = y.c0.from_montgomery();
            let y1_mont = y.c1.from_montgomery();
            for limb in y0_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }
            for limb in y1_mont.limbs.iter() {
                data.extend_from_slice(&limb.to_le_bytes());
            }
        } else {
            data.extend_from_slice(&[0u8; 128]);
        }
        data
    }
}
