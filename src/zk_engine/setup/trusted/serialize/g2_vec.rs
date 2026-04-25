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

use super::g2::deserialize_g2;
use crate::zk_engine::groth16::G2Point;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(super) fn deserialize_g2_vec(
    data: &[u8],
    offset: usize,
) -> Result<(Vec<G2Point>, usize), ZKError> {
    if offset + 4 > data.len() {
        return Err(ZKError::InvalidFormat);
    }

    let count =
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            as usize;
    let mut current = offset + 4;

    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        let (pt, new_offset) = deserialize_g2(data, current)?;
        points.push(pt);
        current = new_offset;
    }

    Ok((points, current))
}
