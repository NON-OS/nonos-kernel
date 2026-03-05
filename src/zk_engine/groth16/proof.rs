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

//! Groth16 proof structure.

use alloc::vec::Vec;
use crate::zk_engine::ZKError;
use super::g1::G1Point;
use super::g2::G2Point;

/// Groth16 proof consisting of three curve points
#[derive(Debug, Clone)]
pub struct Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
    pub circuit_id: u32,
}

impl Proof {
    /// Create a new proof
    pub fn new(a: G1Point, b: G2Point, c: G1Point, circuit_id: u32) -> Self {
        Proof { a, b, c, circuit_id }
    }

    /// Serialize proof to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Serialize A (G1 point - 32 bytes compressed)
        data.extend_from_slice(&self.a.to_bytes());

        // Serialize B (G2 point - 64 bytes compressed)
        data.extend_from_slice(&self.b.to_bytes());

        // Serialize C (G1 point - 32 bytes compressed)
        data.extend_from_slice(&self.c.to_bytes());

        // Serialize circuit ID
        data.extend_from_slice(&self.circuit_id.to_le_bytes());

        data
    }

    /// Deserialize proof from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 132 { // 32 + 64 + 32 + 4
            return Err(ZKError::InvalidProof);
        }

        let a = G1Point::from_bytes(&data[0..32])?;
        let b = G2Point::from_bytes(&data[32..96])?;
        let c = G1Point::from_bytes(&data[96..128])?;
        let circuit_id = u32::from_le_bytes([
            data[128], data[129], data[130], data[131]
        ]);

        Ok(Proof { a, b, c, circuit_id })
    }

    /// Check if proof is valid (basic structure check)
    pub fn is_valid_structure(&self) -> bool {
        // Check points are on curve and not identity
        if self.a.is_identity() {
            return false;
        }
        if self.b.is_identity() {
            return false;
        }
        if self.c.is_identity() {
            return false;
        }

        // Check points are on their respective curves
        if !self.a.is_on_curve() {
            return false;
        }
        if !self.b.is_on_curve() {
            return false;
        }
        if !self.c.is_on_curve() {
            return false;
        }

        true
    }
}
