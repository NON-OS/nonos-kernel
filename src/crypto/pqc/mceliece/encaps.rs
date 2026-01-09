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
use crate::crypto::rng;
use super::{
    MCELIECE_N, MCELIECE_K, MCELIECE_T, MCELIECE_CIPHERTEXT_BYTES, MCELIECE_SHARED_SECRET_BYTES,
    McEliecePublicKey, McElieceCiphertext, hash_error,
};

pub fn mceliece_encaps(pk: &McEliecePublicKey) -> Result<(McElieceCiphertext, [u8; MCELIECE_SHARED_SECRET_BYTES]), &'static str> {
    let mut error = vec![0u8; MCELIECE_N / 8];
    let mut positions: Vec<usize> = (0..MCELIECE_N).collect();
    for i in (MCELIECE_N - MCELIECE_T..MCELIECE_N).rev() {
        let j = rng::random_range((i + 1) as u32) as usize;
        positions.swap(i, j);
    }

    for i in 0..MCELIECE_T {
        let pos = positions[MCELIECE_N - 1 - i];
        error[pos / 8] |= 1 << (pos % 8);
    }

    let r = MCELIECE_N - MCELIECE_K;
    let mut syndrome = vec![0u8; r / 8];
    for i in 0..r / 8 {
        syndrome[i] = error[i];
    }

    let t_row_bytes = MCELIECE_K / 8;
    for row in 0..r {
        let t_offset = row * t_row_bytes;
        let mut bit = 0u8;
        for j in 0..MCELIECE_K / 8 {
            if t_offset + j < pk.t_matrix.len() {
                let e2_byte = error[r / 8 + j];
                let t_byte = pk.t_matrix[t_offset + j];
                bit ^= (e2_byte & t_byte).count_ones() as u8;
            }
        }

        if bit % 2 == 1 {
            syndrome[row / 8] ^= 1 << (row % 8);
        }
    }

    let mut ciphertext = vec![0u8; MCELIECE_CIPHERTEXT_BYTES];
    ciphertext[..syndrome.len()].copy_from_slice(&syndrome);
    ciphertext[syndrome.len()..].fill(0);
    let shared_secret = hash_error(&error);
    Ok((McElieceCiphertext { c: ciphertext }, shared_secret))
}
