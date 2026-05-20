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

const COS_TABLE: [[i32; 8]; 8] = [
    [ 11585,  11585,  11585,  11585,  11585,  11585,  11585,  11585],
    [ 16069,  13623,   9102,   3196,  -3196,  -9102, -13623, -16069],
    [ 15137,   6270,  -6270, -15137, -15137,  -6270,   6270,  15137],
    [ 13623,  -3196, -16069,  -9102,   9102,  16069,   3196, -13623],
    [ 11585, -11585, -11585,  11585,  11585, -11585, -11585,  11585],
    [  9102, -16069,   3196,  13623, -13623,  -3196,  16069,  -9102],
    [  6270, -15137,  15137,  -6270,  -6270,  15137, -15137,   6270],
    [  3196,  -9102,  13623, -16069,  16069, -13623,   9102,  -3196],
];

fn clamp_u8(x: i32) -> u8 {
    if x < 0 {
        0
    } else if x > 255 {
        255
    } else {
        x as u8
    }
}

fn idct_1d_row(coeffs: &[i32; 64], row: usize, scratch: &mut [i32; 64]) {
    let base = row * 8;
    let mut x = 0usize;
    while x < 8 {
        let mut acc: i64 = 0;
        let mut u = 0usize;
        while u < 8 {
            acc += (coeffs[base + u] as i64) * (COS_TABLE[u][x] as i64);
            u += 1;
        }
        scratch[base + x] = ((acc + 8192) >> 14) as i32;
        x += 1;
    }
}

fn idct_1d_col(scratch: &[i32; 64], col: usize, out: &mut [i32; 64]) {
    let mut y = 0usize;
    while y < 8 {
        let mut acc: i64 = 0;
        let mut v = 0usize;
        while v < 8 {
            acc += (scratch[v * 8 + col] as i64) * (COS_TABLE[v][y] as i64);
            v += 1;
        }
        out[y * 8 + col] = ((acc + (1 << 15)) >> 16) as i32;
        y += 1;
    }
}

pub fn idct_8x8(coeffs: &[i32; 64], out: &mut [u8; 64]) {
    let mut scratch: [i32; 64] = [0; 64];
    let mut spatial: [i32; 64] = [0; 64];
    let mut r = 0usize;
    while r < 8 {
        idct_1d_row(coeffs, r, &mut scratch);
        r += 1;
    }
    let mut c = 0usize;
    while c < 8 {
        idct_1d_col(&scratch, c, &mut spatial);
        c += 1;
    }
    let mut i = 0usize;
    while i < 64 {
        out[i] = clamp_u8(spatial[i] + 128);
        i += 1;
    }
}
