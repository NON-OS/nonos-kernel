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

pub fn encode_data(data: &[u8]) -> Option<[u8; 19]> {
    if data.len() > 17 {
        return None;
    }
    let mut bits = [0u8; 152];
    let mut pos = 0;
    write_bits(&mut bits, &mut pos, 0b0100, 4);
    write_bits(&mut bits, &mut pos, data.len() as u32, 8);
    for &b in data {
        write_bits(&mut bits, &mut pos, b as u32, 8);
    }
    let capacity = 152;
    let term_len = core::cmp::min(4, capacity - pos);
    write_bits(&mut bits, &mut pos, 0, term_len);
    while pos % 8 != 0 {
        write_bits(&mut bits, &mut pos, 0, 1);
    }
    let mut pad_byte = 0xEC;
    while pos < capacity {
        write_bits(&mut bits, &mut pos, pad_byte, 8);
        pad_byte = if pad_byte == 0xEC { 0x11 } else { 0xEC };
    }
    Some(bits_to_bytes(&bits))
}

fn write_bits(bits: &mut [u8; 152], pos: &mut usize, val: u32, len: usize) {
    for i in (0..len).rev() {
        if *pos < 152 {
            bits[*pos] = ((val >> i) & 1) as u8;
            *pos += 1;
        }
    }
}

fn bits_to_bytes(bits: &[u8; 152]) -> [u8; 19] {
    let mut bytes = [0u8; 19];
    for i in 0..19 {
        for j in 0..8 {
            bytes[i] |= bits[i * 8 + j] << (7 - j);
        }
    }
    bytes
}
