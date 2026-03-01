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

use core::sync::atomic::{compiler_fence, Ordering};
use super::ops::ct_eq_u32;

#[inline(never)]
pub fn validate_shared_secret(secret: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for byte in secret.iter() {
        acc |= *byte;
    }

    compiler_fence(Ordering::SeqCst);

    acc != 0
}

#[inline(never)]
pub fn verify_clamping(key: &[u8; 32]) -> bool {
    let low_ok = ct_eq_u32((key[0] & 248) as u32, key[0] as u32);
    let high_cleared = ct_eq_u32((key[31] & 127) as u32, key[31] as u32);
    let bit6_set = ct_eq_u32((key[31] | 64) as u32, key[31] as u32);

    compiler_fence(Ordering::SeqCst);

    low_ok == 1 && high_cleared == 1 && bit6_set == 1
}
