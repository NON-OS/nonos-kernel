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

use super::super::{load_u64_le, store_u64_le};
use super::types::FieldElement;
use super::arithmetic::reduce;

impl FieldElement {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut h = [0u64; 5];

        h[0] = load_u64_le(&bytes[0..8]) & 0x7ffffffffffff;
        h[1] = (load_u64_le(&bytes[6..14]) >> 3) & 0x7ffffffffffff;
        h[2] = (load_u64_le(&bytes[12..20]) >> 6) & 0x7ffffffffffff;
        h[3] = (load_u64_le(&bytes[19..27]) >> 1) & 0x7ffffffffffff;
        h[4] = (load_u64_le(&bytes[24..32]) >> 12) & 0x7ffffffffffff;

        FieldElement(h)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut h = reduce(self).0;

        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;

        h[0] += 19 * q;
        let c = h[0] >> 51;
        h[0] &= 0x7ffffffffffff;
        h[1] += c;
        let c = h[1] >> 51;
        h[1] &= 0x7ffffffffffff;
        h[2] += c;
        let c = h[2] >> 51;
        h[2] &= 0x7ffffffffffff;
        h[3] += c;
        let c = h[3] >> 51;
        h[3] &= 0x7ffffffffffff;
        h[4] += c;
        h[4] &= 0x7ffffffffffff;

        let mut bytes = [0u8; 32];
        store_u64_le(&mut bytes[0..8], h[0] | (h[1] << 51));
        store_u64_le(&mut bytes[8..16], (h[1] >> 13) | (h[2] << 38));
        store_u64_le(&mut bytes[16..24], (h[2] >> 26) | (h[3] << 25));
        store_u64_le(&mut bytes[24..32], (h[3] >> 39) | (h[4] << 12));

        bytes
    }
}
