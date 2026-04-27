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

use alloc::vec::Vec;

const ALPHANUMERIC_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn alphanumeric_value(c: u8) -> Option<u8> {
    ALPHANUMERIC_CHARS.iter().position(|&x| x == c).map(|p| p as u8)
}

pub(super) fn encode_alphanumeric(data: &[u8]) -> Option<Vec<u8>> {
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
