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

use super::core::Proof;
use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::g2::G2Point;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl Proof {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.a.to_bytes());
        data.extend_from_slice(&self.b.to_bytes());
        data.extend_from_slice(&self.c.to_bytes());
        data.extend_from_slice(&self.circuit_id.to_le_bytes());
        data
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 132 {
            return Err(ZKError::InvalidProof);
        }

        let a = G1Point::from_bytes(&data[0..32])?;
        let b = G2Point::from_bytes(&data[32..96])?;
        let c = G1Point::from_bytes(&data[96..128])?;
        let circuit_id = u32::from_le_bytes([data[128], data[129], data[130], data[131]]);

        Ok(Proof { a, b, c, circuit_id })
    }
}
