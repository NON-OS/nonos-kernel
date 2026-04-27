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

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    #[inline]
    pub fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }

    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let o = (3 - i) * 8;
            limbs[i] = u64::from_be_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ]);
        }
        Self(limbs)
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let o = (3 - i) * 8;
            bytes[o..o + 8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        bytes
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        let mut r = [0u64; 4];
        let mut c = 0u64;
        for i in 0..4 {
            let (s1, o1) = self.0[i].overflowing_add(other.0[i]);
            let (s2, o2) = s1.overflowing_add(c);
            r[i] = s2;
            c = (o1 as u64) + (o2 as u64);
        }
        if c > 0 {
            None
        } else {
            Some(Self(r))
        }
    }

    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        let mut r = [0u64; 4];
        let mut b = 0u64;
        for i in 0..4 {
            let (d1, u1) = self.0[i].overflowing_sub(other.0[i]);
            let (d2, u2) = d1.overflowing_sub(b);
            r[i] = d2;
            b = (u1 as u64) + (u2 as u64);
        }
        if b > 0 {
            None
        } else {
            Some(Self(r))
        }
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}{:016x}{:016x}{:016x}", self.0[3], self.0[2], self.0[1], self.0[0])
    }
}
