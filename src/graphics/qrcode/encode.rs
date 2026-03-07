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

/*
QR code encoding for Version 2-L (25x25 modules). Supports alphanumeric mode
for Ethereum addresses. Uses Reed-Solomon error correction with 10 EC codewords.
Finder patterns, timing, and format info placed per ISO/IEC 18004.
*/

use alloc::vec::Vec;

const QR_SIZE: usize = 25;
const ALPHANUMERIC_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

pub struct QrCode {
    pub modules: [[bool; QR_SIZE]; QR_SIZE],
    pub size: usize,
}

impl QrCode {
    pub fn new() -> Self {
        Self {
            modules: [[false; QR_SIZE]; QR_SIZE],
            size: QR_SIZE,
        }
    }
}

pub fn encode_qr(data: &[u8]) -> Option<QrCode> {
    if data.len() > 47 {
        return None;
    }

    let mut qr = QrCode::new();
    place_finder_patterns(&mut qr);
    place_timing_patterns(&mut qr);
    place_alignment_pattern(&mut qr);

    let encoded = encode_alphanumeric(data)?;
    let with_ec = add_error_correction(&encoded);
    place_data(&mut qr, &with_ec);
    place_format_info(&mut qr);

    Some(qr)
}

fn place_finder_patterns(qr: &mut QrCode) {
    for (cx, cy) in [(0, 0), (18, 0), (0, 18)] {
        for dy in 0..7 {
            for dx in 0..7 {
                let x = cx + dx;
                let y = cy + dy;
                if x < QR_SIZE && y < QR_SIZE {
                    let is_border = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                    let is_center = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
                    qr.modules[y][x] = is_border || is_center;
                }
            }
        }
    }

    for i in 0..8 {
        if 7 < QR_SIZE { qr.modules[7][i] = false; }
        if i < QR_SIZE { qr.modules[i][7] = false; }
        if 7 < QR_SIZE && 17 + i < QR_SIZE { qr.modules[7][17 + i] = false; }
        if 17 + i < QR_SIZE { qr.modules[17 + i][7] = false; }
        if 17 < QR_SIZE && i < QR_SIZE { qr.modules[17][i] = false; }
        if i < QR_SIZE && 17 < QR_SIZE { qr.modules[i][17] = false; }
    }
}

fn place_timing_patterns(qr: &mut QrCode) {
    for i in 8..17 {
        qr.modules[6][i] = i % 2 == 0;
        qr.modules[i][6] = i % 2 == 0;
    }
}

fn place_alignment_pattern(qr: &mut QrCode) {
    let cx = 18;
    let cy = 18;
    for dy in 0..5 {
        for dx in 0..5 {
            let x = cx - 2 + dx;
            let y = cy - 2 + dy;
            let is_border = dx == 0 || dx == 4 || dy == 0 || dy == 4;
            let is_center = dx == 2 && dy == 2;
            qr.modules[y][x] = is_border || is_center;
        }
    }
}

fn alphanumeric_value(c: u8) -> Option<u8> {
    ALPHANUMERIC_CHARS.iter().position(|&x| x == c).map(|p| p as u8)
}

fn encode_alphanumeric(data: &[u8]) -> Option<Vec<u8>> {
    let mut bits = Vec::new();

    bits.extend_from_slice(&[false, false, true, false]);

    let len = data.len();
    for i in (0..9).rev() {
        bits.push((len >> i) & 1 == 1);
    }

    let mut i = 0;
    while i < data.len() {
        if i + 1 < data.len() {
            let v1 = alphanumeric_value(data[i].to_ascii_uppercase())?;
            let v2 = alphanumeric_value(data[i + 1].to_ascii_uppercase())?;
            let combined = (v1 as u16) * 45 + (v2 as u16);
            for j in (0..11).rev() {
                bits.push((combined >> j) & 1 == 1);
            }
            i += 2;
        } else {
            let v = alphanumeric_value(data[i].to_ascii_uppercase())?;
            for j in (0..6).rev() {
                bits.push((v >> j) & 1 == 1);
            }
            i += 1;
        }
    }

    bits.extend_from_slice(&[false, false, false, false]);

    while bits.len() % 8 != 0 {
        bits.push(false);
    }

    let data_codewords = 34;
    let pad_patterns = [0b11101100u8, 0b00010001u8];
    let mut pad_idx = 0;
    while bits.len() < data_codewords * 8 {
        for j in (0..8).rev() {
            bits.push((pad_patterns[pad_idx] >> j) & 1 == 1);
        }
        pad_idx = 1 - pad_idx;
    }

    let mut bytes = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }

    Some(bytes)
}

fn add_error_correction(data: &[u8]) -> Vec<u8> {
    let ec_codewords = 10;
    let generator: [u8; 11] = [1, 216, 194, 159, 111, 199, 94, 95, 113, 157, 193];

    let mut result = data.to_vec();
    result.resize(data.len() + ec_codewords, 0);

    for i in 0..data.len() {
        let coef = result[i];
        if coef != 0 {
            for j in 0..generator.len() {
                result[i + j] ^= gf_multiply(generator[j], coef);
            }
        }
    }

    let mut final_result = data.to_vec();
    final_result.extend_from_slice(&result[data.len()..]);
    final_result
}

fn gf_multiply(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_a = GF_LOG[a as usize];
    let log_b = GF_LOG[b as usize];
    let log_result = (log_a as u16 + log_b as u16) % 255;
    GF_EXP[log_result as usize]
}

static GF_EXP: [u8; 256] = [
    1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38,
    76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192,
    157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35,
    70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
    95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240,
    253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226,
    217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206,
    129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204,
    133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84,
    168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115,
    230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255,
    227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65,
    130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166,
    81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9,
    18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22,
    44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1,
];

static GF_LOG: [u8; 256] = [
    0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75,
    4, 100, 224, 14, 52, 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113,
    5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240, 18, 130, 69,
    29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166,
    6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136,
    54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64,
    30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61,
    202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87,
    7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24,
    227, 165, 153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46,
    55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97,
    242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162,
    31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
    108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90,
    203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215,
    79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175,
];

fn place_data(qr: &mut QrCode, data: &[u8]) {
    let mut bits = Vec::new();
    for &byte in data {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }

    let mut bit_idx = 0;
    let mut x = QR_SIZE as i32 - 1;
    let mut upward = true;

    while x > 0 {
        if x == 6 {
            x -= 1;
        }

        let col_pair = [x, x - 1];

        if upward {
            for y in (0..QR_SIZE as i32).rev() {
                for &cx in &col_pair {
                    if cx >= 0 && !is_reserved(cx as usize, y as usize) {
                        if bit_idx < bits.len() {
                            qr.modules[y as usize][cx as usize] = bits[bit_idx];
                            bit_idx += 1;
                        }
                    }
                }
            }
        } else {
            for y in 0..QR_SIZE as i32 {
                for &cx in &col_pair {
                    if cx >= 0 && !is_reserved(cx as usize, y as usize) {
                        if bit_idx < bits.len() {
                            qr.modules[y as usize][cx as usize] = bits[bit_idx];
                            bit_idx += 1;
                        }
                    }
                }
            }
        }

        x -= 2;
        upward = !upward;
    }
}

fn is_reserved(x: usize, y: usize) -> bool {
    if x < 9 && y < 9 { return true; }
    if x >= 16 && y < 9 { return true; }
    if x < 9 && y >= 16 { return true; }
    if x == 6 || y == 6 { return true; }
    if x >= 16 && x <= 20 && y >= 16 && y <= 20 { return true; }
    false
}

fn place_format_info(qr: &mut QrCode) {
    let format_bits: u16 = 0b011010101011111;

    for i in 0..6 {
        qr.modules[8][i] = (format_bits >> (14 - i)) & 1 == 1;
    }
    qr.modules[8][7] = (format_bits >> 8) & 1 == 1;
    qr.modules[8][8] = (format_bits >> 7) & 1 == 1;
    qr.modules[7][8] = (format_bits >> 6) & 1 == 1;
    for i in 0..6 {
        qr.modules[5 - i][8] = (format_bits >> i) & 1 == 1;
    }

    for i in 0..8 {
        qr.modules[QR_SIZE - 1 - i][8] = (format_bits >> i) & 1 == 1;
    }
    qr.modules[QR_SIZE - 8][8] = true;
    for i in 0..7 {
        qr.modules[8][QR_SIZE - 7 + i] = (format_bits >> (8 + i)) & 1 == 1;
    }
}
