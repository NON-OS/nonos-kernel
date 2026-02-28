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

use super::types::FieldElement;

const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;

pub(crate) fn reduce(fe: &FieldElement) -> FieldElement {
    let mut limbs = fe.0;

    let c0 = limbs[0] >> 51;
    let c1 = limbs[1] >> 51;
    let c2 = limbs[2] >> 51;
    let c3 = limbs[3] >> 51;
    let c4 = limbs[4] >> 51;

    limbs[0] &= LOW_51_BIT_MASK;
    limbs[1] &= LOW_51_BIT_MASK;
    limbs[2] &= LOW_51_BIT_MASK;
    limbs[3] &= LOW_51_BIT_MASK;
    limbs[4] &= LOW_51_BIT_MASK;

    limbs[0] += c4 * 19;
    limbs[1] += c0;
    limbs[2] += c1;
    limbs[3] += c2;
    limbs[4] += c3;

    let c0 = limbs[0] >> 51;
    let c1 = limbs[1] >> 51;
    let c2 = limbs[2] >> 51;
    let c3 = limbs[3] >> 51;
    let c4 = limbs[4] >> 51;

    limbs[0] &= LOW_51_BIT_MASK;
    limbs[1] &= LOW_51_BIT_MASK;
    limbs[2] &= LOW_51_BIT_MASK;
    limbs[3] &= LOW_51_BIT_MASK;
    limbs[4] &= LOW_51_BIT_MASK;

    limbs[0] += c4 * 19;
    limbs[1] += c0;
    limbs[2] += c1;
    limbs[3] += c2;
    limbs[4] += c3;

    FieldElement(limbs)
}

impl FieldElement {
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        reduce(&FieldElement([
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
        ]))
    }

    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        reduce(&FieldElement([
            (self.0[0] + 36028797018963664u64).wrapping_sub(other.0[0]),
            (self.0[1] + 36028797018963952u64).wrapping_sub(other.0[1]),
            (self.0[2] + 36028797018963952u64).wrapping_sub(other.0[2]),
            (self.0[3] + 36028797018963952u64).wrapping_sub(other.0[3]),
            (self.0[4] + 36028797018963952u64).wrapping_sub(other.0[4]),
        ]))
    }

    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        let a = &self.0;
        let b = &other.0;

        let m0 = (a[0] as u128) * (b[0] as u128);
        let m1 = (a[0] as u128) * (b[1] as u128) + (a[1] as u128) * (b[0] as u128);
        let m2 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128);
        let m3 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128);
        let m4 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);
        let m5 = (a[1] as u128) * (b[4] as u128)
            + (a[2] as u128) * (b[3] as u128)
            + (a[3] as u128) * (b[2] as u128)
            + (a[4] as u128) * (b[1] as u128);
        let m6 = (a[2] as u128) * (b[4] as u128)
            + (a[3] as u128) * (b[3] as u128)
            + (a[4] as u128) * (b[2] as u128);
        let m7 = (a[3] as u128) * (b[4] as u128) + (a[4] as u128) * (b[3] as u128);
        let m8 = (a[4] as u128) * (b[4] as u128);

        let r0 = m0 + 19 * m5;
        let r1 = m1 + 19 * m6;
        let r2 = m2 + 19 * m7;
        let r3 = m3 + 19 * m8;
        let r4 = m4;

        let c = r0 >> 51;
        let h0 = (r0 as u64) & 0x7ffffffffffff;
        let r1 = r1 + c;
        let c = r1 >> 51;
        let h1 = (r1 as u64) & 0x7ffffffffffff;
        let r2 = r2 + c;
        let c = r2 >> 51;
        let h2 = (r2 as u64) & 0x7ffffffffffff;
        let r3 = r3 + c;
        let c = r3 >> 51;
        let h3 = (r3 as u64) & 0x7ffffffffffff;
        let r4 = r4 + c;
        let c = r4 >> 51;
        let h4 = (r4 as u64) & 0x7ffffffffffff;

        let h0 = h0 + (19 * c) as u64;

        reduce(&FieldElement([h0, h1, h2, h3, h4]))
    }

    #[inline]
    pub fn square(&self) -> FieldElement {
        self.mul(self)
    }

    pub fn mul121666(&self) -> FieldElement {
        let mut h = [0u64; 5];
        let mut c = 0u128;

        for i in 0..5 {
            c += (self.0[i] as u128) * 121666;
            h[i] = (c as u64) & 0x7ffffffffffff;
            c >>= 51;
        }
        h[0] += (19 * c) as u64;

        reduce(&FieldElement(h))
    }
}
