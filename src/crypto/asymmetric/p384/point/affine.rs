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
use super::super::{P384_A, P384_B, P384_GX, P384_GY};
use super::types::{AffinePoint, ProjectivePoint};

impl AffinePoint {
    pub fn identity() -> Self {
        Self { x: FieldElement::ZERO, y: FieldElement::ZERO, infinity: true }
    }

    pub fn generator() -> Self {
        Self { x: FieldElement(P384_GX), y: FieldElement(P384_GY), infinity: false }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            49 => Self::from_compressed(bytes.try_into().ok()?),
            97 => Self::from_uncompressed(bytes.try_into().ok()?),
            _ => None,
        }
    }

    pub fn from_compressed(bytes: &[u8; 49]) -> Option<Self> {
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return None;
        }

        let x = FieldElement::from_bytes(bytes[1..49].try_into().ok()?)?;

        let x3 = x.mul(&x).mul(&x);
        let ax = FieldElement(P384_A).mul(&x);
        let y_squared = x3.add(&ax).add(&FieldElement(P384_B));
        let y = y_squared.sqrt()?;

        let y = if (bytes[0] == 0x02) == y.is_even() { y } else { y.negate() };

        Some(Self { x, y, infinity: false })
    }

    pub fn from_uncompressed(bytes: &[u8; 97]) -> Option<Self> {
        if bytes[0] != 0x04 {
            return None;
        }

        let x = FieldElement::from_bytes(bytes[1..49].try_into().ok()?)?;
        let y = FieldElement::from_bytes(bytes[49..97].try_into().ok()?)?;

        let x3 = x.mul(&x).mul(&x);
        let ax = FieldElement(P384_A).mul(&x);
        let y_squared = x3.add(&ax).add(&FieldElement(P384_B));
        if y.mul(&y) != y_squared {
            return None;
        }

        Some(Self { x, y, infinity: false })
    }

    pub fn to_uncompressed(&self) -> [u8; 97] {
        let mut bytes = [0u8; 97];
        bytes[0] = 0x04;
        bytes[1..49].copy_from_slice(&self.x.to_bytes());
        bytes[49..97].copy_from_slice(&self.y.to_bytes());
        bytes
    }

    pub fn to_projective(&self) -> ProjectivePoint {
        if self.infinity {
            ProjectivePoint { x: FieldElement::ZERO, y: FieldElement::ONE, z: FieldElement::ZERO }
        } else {
            ProjectivePoint { x: self.x.clone(), y: self.y.clone(), z: FieldElement::ONE }
        }
    }
}
