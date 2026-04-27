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

use crate::apps::ecosystem::browser::navigate::response::find_header_end;
use alloc::vec::Vec;

pub(super) fn extract_img_body(data: &[u8]) -> Vec<u8> {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let raw_body = &data[header_end + 4..];
        if is_chunked_img(headers) {
            decode_chunked_img(raw_body)
        } else {
            Vec::from(raw_body)
        }
    } else {
        Vec::from(data)
    }
}

fn is_chunked_img(headers: &[u8]) -> bool {
    let s = match core::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") {
            return lower[18..].trim().contains("chunked");
        }
    }
    false
}

fn decode_chunked_img(mut data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let crlf = match data.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => pos,
            None => break,
        };
        let size_str = match core::str::from_utf8(&data[..crlf]) {
            Ok(s) => s.split(';').next().unwrap_or("").trim(),
            Err(_) => break,
        };
        let chunk_len = match usize::from_str_radix(size_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        if chunk_len == 0 {
            break;
        }
        let chunk_start = crlf + 2;
        let chunk_end = chunk_start + chunk_len;
        if chunk_end > data.len() {
            output.extend_from_slice(&data[chunk_start..]);
            break;
        }
        output.extend_from_slice(&data[chunk_start..chunk_end]);
        let next = chunk_end + 2;
        if next > data.len() {
            break;
        }
        data = &data[next..];
    }
    output
}

pub(super) fn wrap_tls_record(content_type: u8, data: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(content_type);
    record.push(0x03);
    record.push(0x03);
    record.push((data.len() >> 8) as u8);
    record.push((data.len() & 0xff) as u8);
    record.extend_from_slice(data);
    record
}
