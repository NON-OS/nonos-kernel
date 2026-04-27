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

use super::helpers::find_sequence;
use alloc::vec::Vec;

pub(super) fn decode_chunked_body(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    loop {
        let size_end = match find_sequence(&data[offset..], b"\r\n") {
            Some(idx) => offset + idx,
            None => break,
        };
        let size_str = &data[offset..size_end];
        let chunk_size = parse_hex_size(size_str)?;
        offset = size_end + 2;
        if chunk_size == 0 {
            break;
        }
        if offset + chunk_size > data.len() {
            result.extend_from_slice(&data[offset..]);
            break;
        }
        result.extend_from_slice(&data[offset..offset + chunk_size]);
        offset += chunk_size;
        if offset + 2 <= data.len() && &data[offset..offset + 2] == b"\r\n" {
            offset += 2;
        }
    }
    Ok(result)
}

fn parse_hex_size(data: &[u8]) -> Result<usize, &'static str> {
    let hex_part =
        if let Some(idx) = data.iter().position(|&b| b == b';') { &data[..idx] } else { data };
    let hex_trimmed: Vec<u8> =
        hex_part.iter().copied().skip_while(|&b| b == b' ' || b == b'\t').collect();
    if hex_trimmed.is_empty() {
        return Ok(0);
    }
    let mut size: usize = 0;
    for &byte in &hex_trimmed {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            b' ' | b'\t' => continue,
            _ => return Err("invalid hex digit in chunk size"),
        };
        size = size
            .checked_mul(16)
            .ok_or("chunk size overflow")?
            .checked_add(digit as usize)
            .ok_or("chunk size overflow")?;
    }
    Ok(size)
}
