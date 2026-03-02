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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::crypto::util::rng::secure_random_u64;
use crate::shell::commands::utils::{trim_bytes, format_hex_byte};

pub fn cmd_random(cmd: &[u8]) {
    let args = if cmd.len() > 7 {
        trim_bytes(&cmd[7..])
    } else {
        b"hex" as &[u8]
    };

    print_line(b"Secure Random Data:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    match args {
        b"hex" | b"" => {
            random_hex();
        }
        b"u64" | b"int" => {
            random_u64();
        }
        b"bytes" => {
            random_bytes();
        }
        _ => {
            print_line(b"Usage: random [hex|u64|bytes]", COLOR_TEXT_DIM);
        }
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Source: Hardware RNG (RDRAND)", COLOR_TEXT_DIM);
}

fn random_hex() {
    let r1 = secure_random_u64();
    let r2 = secure_random_u64();
    let r3 = secure_random_u64();
    let r4 = secure_random_u64();

    print_line(b"Format: Hexadecimal (256 bits)", COLOR_TEXT_DIM);

    let mut line = [0u8; 68];
    line[0] = b' ';
    line[1] = b' ';

    let bytes1 = r1.to_be_bytes();
    let bytes2 = r2.to_be_bytes();
    let bytes3 = r3.to_be_bytes();
    let bytes4 = r4.to_be_bytes();

    for i in 0..8 {
        format_hex_byte(&mut line[2 + i * 2..], bytes1[i]);
        format_hex_byte(&mut line[18 + i * 2..], bytes2[i]);
        format_hex_byte(&mut line[34 + i * 2..], bytes3[i]);
        format_hex_byte(&mut line[50 + i * 2..], bytes4[i]);
    }

    print_line(&line[..66], COLOR_GREEN);
}

fn random_u64() {
    let r = secure_random_u64();
    print_line(b"Format: 64-bit unsigned integer", COLOR_TEXT_DIM);

    let mut line = [0u8; 32];
    line[0] = b' ';
    line[1] = b' ';

    let mut val = r;
    let mut digits = [0u8; 20];
    let mut pos = 0;
    if val == 0 {
        digits[0] = b'0';
        pos = 1;
    } else {
        while val > 0 {
            digits[pos] = b'0' + (val % 10) as u8;
            val /= 10;
            pos += 1;
        }
    }

    for i in 0..pos {
        line[2 + i] = digits[pos - 1 - i];
    }

    print_line(&line[..2 + pos], COLOR_GREEN);
}

fn random_bytes() {
    let r1 = secure_random_u64();
    let r2 = secure_random_u64();
    print_line(b"Format: Raw bytes (base64-like)", COLOR_TEXT_DIM);

    let mut line = [0u8; 48];
    line[0] = b' ';
    line[1] = b' ';

    let bytes1 = r1.to_be_bytes();
    let bytes2 = r2.to_be_bytes();

    for i in 0..8 {
        line[2 + i] = if bytes1[i] >= 32 && bytes1[i] < 127 {
            bytes1[i]
        } else {
            b'.'
        };
        line[10 + i] = if bytes2[i] >= 32 && bytes2[i] < 127 {
            bytes2[i]
        } else {
            b'.'
        };
    }

    print_line(&line[..18], COLOR_GREEN);
}
