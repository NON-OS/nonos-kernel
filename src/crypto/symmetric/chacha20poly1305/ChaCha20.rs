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

use crate::crypto::constant_time::compiler_fence;

pub const CHACHA20_BLOCK_SIZE: usize = 64;

pub(crate) const CHACHA_CONSTANT: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[inline]
pub(crate) fn secure_zero_bytes(buf: &mut [u8]) {
    for b in buf {
        // SAFETY: We have exclusive mutable access to buf, and volatile write ensures
        // the compiler cannot optimize away this zeroing operation.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence();
}

#[inline]
pub(crate) fn secure_zero_u32(buf: &mut [u32]) {
    for w in buf {
        // SAFETY: We have exclusive mutable access to buf, and volatile write ensures
        // the compiler cannot optimize away this zeroing operation.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence();
}

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 64]) {
    let mut state = [0u32; 16];

    state[0] = CHACHA_CONSTANT[0];
    state[1] = CHACHA_CONSTANT[1];
    state[2] = CHACHA_CONSTANT[2];
    state[3] = CHACHA_CONSTANT[3];

    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    state[12] = counter;

    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let initial = state;

    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    for i in 0..16 {
        let word = state[i].wrapping_add(initial[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
}

pub(crate) fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut block = [0u8; 64];
    let mut block_counter = counter;
    let mut offset = 0;

    while offset < data.len() {
        chacha20_block(key, nonce, block_counter, &mut block);

        let remaining = data.len() - offset;
        let to_xor = core::cmp::min(64, remaining);
        for i in 0..to_xor {
            data[offset + i] ^= block[i];
        }

        offset += to_xor;
        block_counter = block_counter.wrapping_add(1);
    }

    secure_zero_bytes(&mut block);
}
