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

extern crate alloc;

use alloc::vec::Vec;

pub fn decode(data: &str) -> Result<Vec<u8>, ()> {
    decode_bytes(data.as_bytes())
}

fn decode_bytes(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut result = Vec::new();
    let mut buf = [0u8; 4];
    let mut buf_len = 0;

    for &c in data {
        if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
            continue;
        }

        let val = if c >= b'A' && c <= b'Z' {
            c - b'A'
        } else if c >= b'a' && c <= b'z' {
            c - b'a' + 26
        } else if c >= b'0' && c <= b'9' {
            c - b'0' + 52
        } else if c == b'+' {
            62
        } else if c == b'/' {
            63
        } else if c == b'=' {
            64
        } else {
            return Err(());
        };

        buf[buf_len] = val;
        buf_len += 1;

        if buf_len == 4 {
            result.push((buf[0] << 2) | (buf[1] >> 4));
            if buf[2] != 64 {
                result.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if buf[3] != 64 {
                result.push((buf[2] << 6) | buf[3]);
            }
            buf_len = 0;
        }
    }

    Ok(result)
}
