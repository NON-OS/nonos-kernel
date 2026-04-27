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

impl BigUint {
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
        let num_limbs = padded_len / 16;
        let mut limbs = vec![0u64; num_limbs];
        for (i, chunk) in s.as_bytes().chunks(16).enumerate() {
            let chunk_str = core::str::from_utf8(chunk).ok()?;
            let limb_idx = num_limbs - 1 - i;
            let val = u64::from_str_radix(chunk_str, 16).ok()?;
            limbs[limb_idx] = val;
        }
        Some(Self::normalize(limbs))
    }
}
