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

extern crate alloc;
use super::types::BigUint;
use alloc::vec;
use alloc::vec::Vec;

impl BigUint {
    #[inline]
    pub fn zero() -> Self {
        Self { limbs: vec![0] }
    }
    #[inline]
    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }
    #[inline]
    pub fn new() -> Self {
        Self::zero()
    }
    #[inline]
    pub fn from_u64(val: u64) -> Self {
        Self { limbs: vec![val] }
    }

    pub fn from_u128(val: u128) -> Self {
        if val == 0 {
            return Self::zero();
        }
        let lo = val as u64;
        let hi = (val >> 64) as u64;
        if hi == 0 {
            Self { limbs: vec![lo] }
        } else {
            Self { limbs: vec![lo, hi] }
        }
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
            return Self::zero();
        }
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let bytes = &bytes[start..];
        if bytes.is_empty() {
            return Self::zero();
        }
        let num_limbs = (bytes.len() + 7) / 8;
        let mut limbs = vec![0u64; num_limbs];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            let limb_idx = i / 8;
            let byte_idx = i % 8;
            limbs[limb_idx] |= (byte as u64) << (byte_idx * 8);
        }
        Self::normalize(limbs)
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
            return Self::zero();
        }
        let num_limbs = (bytes.len() + 7) / 8;
        let mut limbs = vec![0u64; num_limbs];
        for (i, &byte) in bytes.iter().enumerate() {
            let limb_idx = i / 8;
            let byte_idx = i % 8;
            limbs[limb_idx] |= (byte as u64) << (byte_idx * 8);
        }
        Self::normalize(limbs)
    }

    pub(crate) fn normalize(mut limbs: Vec<u64>) -> Self {
        while limbs.len() > 1 && limbs.last() == Some(&0) {
            limbs.pop();
        }
        if limbs.is_empty() {
            limbs.push(0);
        }
        Self { limbs }
    }
}
