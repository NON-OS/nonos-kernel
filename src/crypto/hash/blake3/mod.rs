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

#![allow(clippy::many_single_char_names)]
#![allow(clippy::identity_op)]

extern crate alloc;

mod compress;
mod chunk;
mod output;
mod hasher;

#[cfg(test)]
mod tests;

pub use hasher::Hasher;
pub use output::OutputReader;

pub const OUT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const ROUNDS: usize = 7;
const MAX_DEPTH: usize = 54;

const CHUNK_START: u8         = 1 << 0;
const CHUNK_END: u8           = 1 << 1;
const PARENT: u8              = 1 << 2;
const ROOT: u8                = 1 << 3;
const KEYED_HASH: u8          = 1 << 4;
const DERIVE_KEY_CONTEXT: u8  = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

pub fn blake3_hash(input: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

pub fn blake3_hash_xof(input: &[u8], output: &mut [u8]) {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize_xof().fill(output);
}

pub fn blake3_keyed_hash(key: &[u8; KEY_LEN], input: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(input);
    hasher.finalize()
}

pub fn blake3_derive_key(context: &str, key_material: &[u8], output: &mut [u8]) {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(key_material);
    hasher.finalize_xof().fill(output);
}
