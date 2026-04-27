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

use crate::crypto::hash::blake3_keyed_hash;

const LIONESS_ROUNDS: usize = 4;

pub fn lioness_encrypt(key: &[u8; 32], data: &mut [u8]) {
    if data.len() < 64 {
        return;
    }
    let (left, right) = data.split_at_mut(32);
    for round in 0..LIONESS_ROUNDS {
        let round_key = derive_round_key(key, round as u8);
        let h = blake3_keyed_hash(&round_key, right);
        xor_block(left, &h);
        let stream_key = derive_round_key(key, (round as u8).wrapping_add(128));
        stream_xor(&stream_key, right);
    }
}

pub fn lioness_decrypt(key: &[u8; 32], data: &mut [u8]) {
    if data.len() < 64 {
        return;
    }
    let (left, right) = data.split_at_mut(32);
    for round in (0..LIONESS_ROUNDS).rev() {
        let stream_key = derive_round_key(key, (round as u8).wrapping_add(128));
        stream_xor(&stream_key, right);
        let round_key = derive_round_key(key, round as u8);
        let h = blake3_keyed_hash(&round_key, right);
        xor_block(left, &h);
    }
}

fn derive_round_key(master: &[u8; 32], round: u8) -> [u8; 32] {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(master);
    input[32] = round;
    blake3_keyed_hash(master, &input)
}

fn stream_xor(key: &[u8; 32], data: &mut [u8]) {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    state[12] = 0;
    state[13] = 0;
    state[14] = 0;
    state[15] = 0;
    let mut offset = 0;
    while offset < data.len() {
        let block = chacha_block(&state);
        state[12] = state[12].wrapping_add(1);
        for i in 0..64.min(data.len() - offset) {
            data[offset + i] ^= block[i];
        }
        offset += 64;
    }
}

fn chacha_block(state: &[u32; 16]) -> [u8; 64] {
    let mut s = *state;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 {
        s[i] = s[i].wrapping_add(state[i]);
    }
    let mut out = [0u8; 64];
    for (i, w) in s.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn xor_block(dest: &mut [u8], src: &[u8; 32]) {
    for i in 0..dest.len().min(32) {
        dest[i] ^= src[i];
    }
}
