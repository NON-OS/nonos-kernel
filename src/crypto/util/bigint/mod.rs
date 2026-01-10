// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::constant_time::compiler_fence;

mod arithmetic;
mod bitops;
mod conversion;
mod division;
mod modular;
mod primality;

#[cfg(test)]
mod tests;

pub use arithmetic::*;
pub use bitops::*;
pub use conversion::*;
pub use division::*;
pub use modular::*;
pub use primality::*;

pub(crate) const LIMB_BITS: usize = 64;
#[allow(dead_code)]
pub(crate) const LIMB_MAX: u64 = u64::MAX;

#[derive(Clone, Eq)]
pub struct BigUint {
    pub(crate) limbs: Vec<u64>,
}

impl Drop for BigUint {
    fn drop(&mut self) {
        for limb in &mut self.limbs {
            // SAFETY: We're writing to valid memory that we own, and the volatile
            // write ensures the compiler doesn't optimize away the zeroing.
            unsafe {
                core::ptr::write_volatile(limb, 0);
            }
        }
        compiler_fence();
    }
}

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
            Self::zero()
        } else {
            let lo = val as u64;
            let hi = (val >> 64) as u64;
            if hi == 0 {
                Self { limbs: vec![lo] }
            } else {
                Self { limbs: vec![lo, hi] }
            }
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

    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

        if s.is_empty() {
            return Some(Self::zero());
        }

        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        let padded_len = ((s.len() + 15) / 16) * 16;
        let padding = padded_len - s.len();

        let num_limbs = padded_len / 16;
        let mut limbs = vec![0u64; num_limbs];

        for (i, chunk) in s.as_bytes().chunks(16).enumerate() {
            let chunk_str = core::str::from_utf8(chunk).ok()?;
            let limb_idx = num_limbs - 1 - i;

            if i == 0 && padding > 0 {
                let val = u64::from_str_radix(chunk_str, 16).ok()?;
                limbs[limb_idx] = val;
            } else {
                let val = u64::from_str_radix(chunk_str, 16).ok()?;
                limbs[limb_idx] = val;
            }
        }

        Some(Self::normalize(limbs))
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

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 0
    }

    #[inline]
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }

    #[inline]
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }

    #[inline]
    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    pub fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let top_limb = self.limbs[self.limbs.len() - 1];
        let top_bits = LIMB_BITS - top_limb.leading_zeros() as usize;
        (self.limbs.len() - 1) * LIMB_BITS + top_bits
    }

    #[inline]
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    #[inline]
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }
}

impl Default for BigUint {
    fn default() -> Self {
        Self::zero()
    }
}
