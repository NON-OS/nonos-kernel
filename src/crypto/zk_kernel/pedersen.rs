// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use alloc::vec::Vec;

use crate::crypto::hash::blake3_hash;
use crate::crypto::curve25519::EdwardsPoint;
use super::constants::DOM_PEDERSEN;
use super::utils::constant_time_eq;

const BASEPOINT_G: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

fn derive_generator_h() -> EdwardsPoint {
    let mut seed = Vec::with_capacity(DOM_PEDERSEN.len() + 11);
    seed.extend_from_slice(DOM_PEDERSEN);
    seed.extend_from_slice(b"generator_h");

    let mut counter = 0u32;
    loop {
        let mut data = seed.clone();
        data.extend_from_slice(&counter.to_le_bytes());
        let hash = blake3_hash(&data);

        if let Some(point) = EdwardsPoint::decompress(&hash) {
            let cofactor_cleared = point.double().double().double();
            if !cofactor_cleared.is_identity() {
                return cofactor_cleared;
            }
        }
        counter += 1;
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PedersenCommitment {
    pub commitment: [u8; 32],
}

impl PedersenCommitment {
    pub fn commit(value: &[u8; 32], blinding: &[u8; 32]) -> Self {
        let g = match EdwardsPoint::decompress(&BASEPOINT_G) {
            Some(p) => p,
            None => return Self { commitment: [0u8; 32] },
        };
        let h = derive_generator_h();

        let v_g = g.scalar_mul(value);
        let r_h = h.scalar_mul(blinding);
        let commitment_point = v_g.add(&r_h);

        Self {
            commitment: commitment_point.compress(),
        }
    }

    pub fn commit_u64(value: u64, blinding: &[u8; 32]) -> Self {
        let mut value_bytes = [0u8; 32];
        value_bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self::commit(&value_bytes, blinding)
    }

    pub fn verify(&self, value: &[u8; 32], blinding: &[u8; 32]) -> bool {
        let expected = Self::commit(value, blinding);
        constant_time_eq(&self.commitment, &expected.commitment)
    }

    pub fn to_point(&self) -> Option<EdwardsPoint> {
        EdwardsPoint::decompress(&self.commitment)
    }

    pub fn from_point(point: &EdwardsPoint) -> Self {
        Self {
            commitment: point.compress(),
        }
    }

    pub fn add(&self, other: &Self) -> Option<Self> {
        let p1 = self.to_point()?;
        let p2 = other.to_point()?;
        Some(Self::from_point(&p1.add(&p2)))
    }

    pub fn sub(&self, other: &Self) -> Option<Self> {
        let p1 = self.to_point()?;
        let p2 = other.to_point()?;
        Some(Self::from_point(&p1.add(&p2.negate())))
    }

    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Option<Self> {
        let p = self.to_point()?;
        Some(Self::from_point(&p.scalar_mul(scalar)))
    }

    pub fn generator_g() -> Option<EdwardsPoint> {
        EdwardsPoint::decompress(&BASEPOINT_G)
    }

    pub fn generator_h() -> EdwardsPoint {
        derive_generator_h()
    }
}
