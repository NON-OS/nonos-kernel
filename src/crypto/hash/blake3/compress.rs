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

use super::{IV, MSG_SCHEDULE, ROUNDS, BLOCK_LEN};

#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline(always)]
fn round(state: &mut [u32; 16], m: &[u32; 16], schedule: &[usize; 16]) {
    g(state, 0, 4,  8, 12, m[schedule[0]],  m[schedule[1]]);
    g(state, 1, 5,  9, 13, m[schedule[2]],  m[schedule[3]]);
    g(state, 2, 6, 10, 14, m[schedule[4]],  m[schedule[5]]);
    g(state, 3, 7, 11, 15, m[schedule[6]],  m[schedule[7]]);
    g(state, 0, 5, 10, 15, m[schedule[8]],  m[schedule[9]]);
    g(state, 1, 6, 11, 12, m[schedule[10]], m[schedule[11]]);
    g(state, 2, 7,  8, 13, m[schedule[12]], m[schedule[13]]);
    g(state, 3, 4,  9, 14, m[schedule[14]], m[schedule[15]]);
}

#[inline]
pub(crate) fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u8,
) -> [u32; 16] {
    let mut state = [
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags as u32,
    ];

    for r in 0..ROUNDS {
        round(&mut state, block, &MSG_SCHEDULE[r]);
    }

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }

    state
}

#[inline]
pub(crate) fn first_8_words(state: &[u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&state[..8]);
    cv
}

#[inline]
pub(crate) fn words_from_le_bytes(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

#[inline]
pub(crate) fn words_to_le_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    bytes
}
