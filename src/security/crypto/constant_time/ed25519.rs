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
use super::ops::ct_lt_u32;

#[inline(never)]
pub fn validate_secret_key(key: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for byte in key.iter() {
        acc |= *byte;
    }

    compiler_fence(Ordering::SeqCst);

    acc != 0
}

#[inline(never)]
pub fn validate_signature_format(sig: &[u8; 64]) -> bool {
    let s_high = sig[63];

    let valid = ct_lt_u32(s_high as u32, 0x80);

    compiler_fence(Ordering::SeqCst);

    valid == 1
}
