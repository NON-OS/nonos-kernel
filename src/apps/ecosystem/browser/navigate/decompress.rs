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

use alloc::string::String;
use alloc::vec::Vec;

pub fn get_content_encoding(headers: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-encoding:") {
            return Some(String::from(lower[17..].trim()));
        }
    }
    None
}

pub fn decompress_body(body: &[u8], encoding: Option<&str>) -> Vec<u8> {
    match encoding {
        Some("gzip") | Some("x-gzip") => decompress_gzip(body).unwrap_or_else(|| body.to_vec()),
        Some("deflate") => decompress_deflate(body).unwrap_or_else(|| body.to_vec()),
        Some("br") => body.to_vec(),
        _ => body.to_vec(),
    }
}

fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B { return None; }
    let flags = data[3];
    let mut offset: usize = 10;
    if flags & 0x04 != 0 && data.len() > offset + 2 {
        let xlen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        while offset < data.len() && data[offset] != 0 { offset += 1; }
        offset += 1;
    }
    if flags & 0x10 != 0 {
        while offset < data.len() && data[offset] != 0 { offset += 1; }
        offset += 1;
    }
    if flags & 0x02 != 0 { offset += 2; }
    if offset >= data.len() { return None; }
    let deflate_data = &data[offset..data.len().saturating_sub(8)];
    miniz_oxide::inflate::decompress_to_vec(deflate_data).ok()
}

fn decompress_deflate(data: &[u8]) -> Option<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib(data)
        .or_else(|_| miniz_oxide::inflate::decompress_to_vec(data))
        .ok()
}
