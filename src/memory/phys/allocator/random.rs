// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::constants::{FALLBACK_SEED, SPLITMIX64_GOLDEN, SPLITMIX64_MIX1, SPLITMIX64_MIX2};

pub fn derive_seed() -> u64 {
    if let Ok(nonce) = crate::memory::kaslr::boot_nonce() {
        nonce.wrapping_add(SPLITMIX64_GOLDEN)
    } else {
        FALLBACK_SEED
    }
}

#[inline]
pub fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX64_MIX1);
    z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX64_MIX2);
    z ^ (z >> 31)
}
