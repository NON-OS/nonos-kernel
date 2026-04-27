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

use super::limbs::{bytes_to_u64_limbs, u64_limbs_to_bytes};
use crate::zk_engine::groth16::{FieldElement, G1Point};
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(super) fn serialize_g1(pt: &G1Point, out: &mut Vec<u8>) {
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.x.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.y.limbs));
}

pub(super) fn deserialize_g1(data: &[u8], offset: usize) -> Result<(G1Point, usize), ZKError> {
    if offset + 64 > data.len() {
        return Err(ZKError::InvalidFormat);
    }

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&data[offset..offset + 32]);
    y_bytes.copy_from_slice(&data[offset + 32..offset + 64]);

    Ok((
        G1Point {
            x: FieldElement { limbs: bytes_to_u64_limbs(&x_bytes) },
            y: FieldElement { limbs: bytes_to_u64_limbs(&y_bytes) },
            z: FieldElement::one(),
        },
        offset + 64,
    ))
}

pub(super) fn deserialize_g1_vec(
    data: &[u8],
    offset: usize,
) -> Result<(Vec<G1Point>, usize), ZKError> {
    if offset + 4 > data.len() {
        return Err(ZKError::InvalidFormat);
    }

    let count =
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            as usize;
    let mut current = offset + 4;

    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        let (pt, new_offset) = deserialize_g1(data, current)?;
        points.push(pt);
        current = new_offset;
    }

    Ok((points, current))
}
