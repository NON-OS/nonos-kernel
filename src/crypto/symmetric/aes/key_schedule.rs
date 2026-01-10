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

use crate::crypto::constant_time::{ct_lookup_u8, compiler_fence};
use super::core::SBOX;
use super::RCON;

#[inline]
pub(crate) fn rot_word(x: u32) -> u32 {
    (x << 8) | (x >> 24)
}

#[inline(never)]
pub(crate) fn sub_word_ct(x: u32) -> u32 {
    let b = x.to_be_bytes();
    let y = [
        ct_lookup_u8(&SBOX, b[0]),
        ct_lookup_u8(&SBOX, b[1]),
        ct_lookup_u8(&SBOX, b[2]),
        ct_lookup_u8(&SBOX, b[3]),
    ];
    u32::from_be_bytes(y)
}

pub(crate) fn expand_key_128(key: &[u8; 16], round_keys: &mut [[u8; 16]; 11]) {
    let mut w = [0u32; 44];
    for i in 0..4 {
        let j = i * 4;
        w[i] = u32::from_be_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
    }

    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = sub_word_ct(rot_word(temp)) ^ u32::from_be_bytes([RCON[i / 4 - 1], 0, 0, 0]);
        }
        w[i] = w[i - 4] ^ temp;
    }

    for r in 0..11 {
        let base = r * 4;
        round_keys[r][0..4].copy_from_slice(&w[base].to_be_bytes());
        round_keys[r][4..8].copy_from_slice(&w[base + 1].to_be_bytes());
        round_keys[r][8..12].copy_from_slice(&w[base + 2].to_be_bytes());
        round_keys[r][12..16].copy_from_slice(&w[base + 3].to_be_bytes());
    }

    for word in &mut w {
        // SAFETY: Volatile write ensures the compiler does not optimize away zeroing
        unsafe { core::ptr::write_volatile(word, 0) };
    }
    compiler_fence();
}

pub(crate) fn expand_key_256(key: &[u8; 32], round_keys: &mut [[u8; 16]; 15]) {
    let mut w = [0u32; 60];

    for i in 0..8 {
        let j = i * 4;
        w[i] = u32::from_be_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
    }

    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = sub_word_ct(rot_word(temp)) ^ u32::from_be_bytes([RCON[i / 8 - 1], 0, 0, 0]);
        } else if i % 8 == 4 {
            temp = sub_word_ct(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }

    for r in 0..15 {
        let base = r * 4;
        round_keys[r][0..4].copy_from_slice(&w[base].to_be_bytes());
        round_keys[r][4..8].copy_from_slice(&w[base + 1].to_be_bytes());
        round_keys[r][8..12].copy_from_slice(&w[base + 2].to_be_bytes());
        round_keys[r][12..16].copy_from_slice(&w[base + 3].to_be_bytes());
    }

    for word in &mut w {
        // SAFETY: Volatile write ensures the compiler does not optimize away zeroing
        unsafe { core::ptr::write_volatile(word, 0) };
    }
    compiler_fence();
}
