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
use super::super::util::find_subsequence;

pub(super) fn is_chunked_complete(body: &[u8]) -> bool {
    if body.len() >= 5 {
        if body.ends_with(b"0\r\n\r\n") {
            return true;
        }
        if let Some(idx) = find_subsequence(body, b"\r\n0\r\n") {
            let remaining = &body[idx + 5..];
            if remaining.is_empty() || remaining.ends_with(b"\r\n") {
                return true;
            }
        }
    }
    false
}

pub(super) fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;

    while offset < data.len() {
        let size_end = match find_subsequence(&data[offset..], b"\r\n") {
            Some(idx) => offset + idx,
            None => break,
        };

        let size_str = &data[offset..size_end];
        let chunk_size = match parse_hex_chunk_size(size_str) {
            Some(s) => s,
            None => break,
        };

        offset = size_end + 2;

        if chunk_size == 0 {
            break;
        }

        if offset + chunk_size <= data.len() {
            result.extend_from_slice(&data[offset..offset + chunk_size]);
            offset += chunk_size;
        } else {
            result.extend_from_slice(&data[offset..]);
            break;
        }

        if offset + 2 <= data.len() && &data[offset..offset + 2] == b"\r\n" {
            offset += 2;
        }
    }

    result
}

fn parse_hex_chunk_size(data: &[u8]) -> Option<usize> {
    let hex_end = data.iter().position(|&b| b == b';').unwrap_or(data.len());
    let hex_str = &data[..hex_end];

    let mut size: usize = 0;
    for &byte in hex_str {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            b' ' | b'\t' => continue,
            _ => return None,
        };
        size = size.checked_mul(16)?.checked_add(digit as usize)?;
    }

    Some(size)
}
