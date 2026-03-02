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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};

pub(super) fn print_key_count(prefix: &[u8], count: usize) {
    let mut line = [0u8; 32];
    let plen = prefix.len().min(20);
    line[..plen].copy_from_slice(&prefix[..plen]);

    let mut num = count;
    let mut digits = [0u8; 10];
    let mut dpos = 0;
    if num == 0 {
        digits[0] = b'0';
        dpos = 1;
    } else {
        while num > 0 && dpos < 10 {
            digits[dpos] = b'0' + (num % 10) as u8;
            num /= 10;
            dpos += 1;
        }
    }

    let mut pos = plen;
    for i in (0..dpos).rev() {
        line[pos] = digits[i];
        pos += 1;
    }

    print_line(&line[..pos], COLOR_TEXT_DIM);
}

pub(super) fn print_key_id(key_id: &[u8]) {
    let mut line = [0u8; 48];
    line[..4].copy_from_slice(b"  - ");
    let len = key_id.len().min(40);
    line[4..4+len].copy_from_slice(&key_id[..len]);
    print_line(&line[..4+len], COLOR_TEXT);
}

pub(super) fn print_keypair_id(key_id: u32) {
    let mut line = [0u8; 24];
    line[..11].copy_from_slice(b"  - Key ID ");

    let mut num = key_id;
    let mut digits = [0u8; 10];
    let mut dpos = 0;
    if num == 0 {
        digits[0] = b'0';
        dpos = 1;
    } else {
        while num > 0 && dpos < 10 {
            digits[dpos] = b'0' + (num % 10) as u8;
            num /= 10;
            dpos += 1;
        }
    }

    let mut pos = 11;
    for i in (0..dpos).rev() {
        line[pos] = digits[i];
        pos += 1;
    }

    print_line(&line[..pos], COLOR_TEXT);
}

pub(super) fn print_hex_key(key: &[u8; 32]) {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut line1 = [0u8; 36];
    let mut line2 = [0u8; 36];
    line1[0..2].copy_from_slice(b"  ");
    line2[0..2].copy_from_slice(b"  ");

    for i in 0..16 {
        line1[2 + i*2] = HEX[(key[i] >> 4) as usize];
        line1[2 + i*2 + 1] = HEX[(key[i] & 0xf) as usize];
    }
    for i in 0..16 {
        line2[2 + i*2] = HEX[(key[16+i] >> 4) as usize];
        line2[2 + i*2 + 1] = HEX[(key[16+i] & 0xf) as usize];
    }

    print_line(&line1[..34], COLOR_TEXT_WHITE);
    print_line(&line2[..34], COLOR_TEXT_WHITE);
}

pub(super) fn print_hex_signature(sig: &[u8; 64]) {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut line1 = [0u8; 36];
    let mut line2 = [0u8; 36];
    let mut line3 = [0u8; 36];
    let mut line4 = [0u8; 36];

    line1[0..2].copy_from_slice(b"  ");
    line2[0..2].copy_from_slice(b"  ");
    line3[0..2].copy_from_slice(b"  ");
    line4[0..2].copy_from_slice(b"  ");

    for i in 0..16 {
        line1[2 + i*2] = HEX[(sig[i] >> 4) as usize];
        line1[2 + i*2 + 1] = HEX[(sig[i] & 0xf) as usize];
    }
    for i in 0..16 {
        line2[2 + i*2] = HEX[(sig[16+i] >> 4) as usize];
        line2[2 + i*2 + 1] = HEX[(sig[16+i] & 0xf) as usize];
    }
    for i in 0..16 {
        line3[2 + i*2] = HEX[(sig[32+i] >> 4) as usize];
        line3[2 + i*2 + 1] = HEX[(sig[32+i] & 0xf) as usize];
    }
    for i in 0..16 {
        line4[2 + i*2] = HEX[(sig[48+i] >> 4) as usize];
        line4[2 + i*2 + 1] = HEX[(sig[48+i] & 0xf) as usize];
    }

    print_line(&line1[..34], COLOR_TEXT_WHITE);
    print_line(&line2[..34], COLOR_TEXT_WHITE);
    print_line(&line3[..34], COLOR_TEXT_WHITE);
    print_line(&line4[..34], COLOR_TEXT_WHITE);
}

pub(super) fn print_hex_nonce(nonce: &[u8; 12]) {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut line = [0u8; 28];
    line[0..2].copy_from_slice(b"  ");

    for i in 0..12 {
        line[2 + i*2] = HEX[(nonce[i] >> 4) as usize];
        line[2 + i*2 + 1] = HEX[(nonce[i] & 0xf) as usize];
    }

    print_line(&line[..26], COLOR_TEXT_WHITE);
}

pub(super) fn print_hex_data(data: &[u8]) {
    const HEX: &[u8] = b"0123456789abcdef";
    let len = data.len().min(32);
    let mut line = [0u8; 68];
    line[0..2].copy_from_slice(b"  ");

    for i in 0..len {
        line[2 + i*2] = HEX[(data[i] >> 4) as usize];
        line[2 + i*2 + 1] = HEX[(data[i] & 0xf) as usize];
    }

    print_line(&line[..2+len*2], COLOR_TEXT_WHITE);

    if data.len() > 32 {
        print_line(b"  ... (truncated)", COLOR_TEXT_DIM);
    }
}
