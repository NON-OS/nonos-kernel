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
use crate::zk_engine::groth16::{FieldElement, G2FieldElement, G2Point};
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(super) fn serialize_g2(pt: &G2Point, out: &mut Vec<u8>) {
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.x.c0.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.x.c1.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.y.c0.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.y.c1.limbs));
}

pub(super) fn deserialize_g2(data: &[u8], offset: usize) -> Result<(G2Point, usize), ZKError> {
    if offset + 128 > data.len() {
        return Err(ZKError::InvalidFormat);
    }

    let mut c0_x = [0u8; 32];
    let mut c1_x = [0u8; 32];
    let mut c0_y = [0u8; 32];
    let mut c1_y = [0u8; 32];

    c0_x.copy_from_slice(&data[offset..offset + 32]);
    c1_x.copy_from_slice(&data[offset + 32..offset + 64]);
    c0_y.copy_from_slice(&data[offset + 64..offset + 96]);
    c1_y.copy_from_slice(&data[offset + 96..offset + 128]);

    Ok((
        G2Point {
            x: G2FieldElement {
                c0: FieldElement { limbs: bytes_to_u64_limbs(&c0_x) },
                c1: FieldElement { limbs: bytes_to_u64_limbs(&c1_x) },
            },
            y: G2FieldElement {
                c0: FieldElement { limbs: bytes_to_u64_limbs(&c0_y) },
                c1: FieldElement { limbs: bytes_to_u64_limbs(&c1_y) },
            },
            z: G2FieldElement::one(),
        },
        offset + 128,
    ))
}
