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
use super::parse::{find_header_end, is_chunked_transfer};

pub fn extract_body(data: &[u8]) -> Vec<u8> {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let raw_body = &data[header_end + 4..];
        let body = if is_chunked_transfer(headers) { decode_chunked(raw_body) } else { Vec::from(raw_body) };
        let enc = crate::apps::ecosystem::browser::navigate::decompress::get_content_encoding(headers);
        crate::sys::serial::print(b"[NAV] encoding=");
        crate::sys::serial::println(enc.as_deref().unwrap_or("none").as_bytes());
        crate::sys::serial::print(b"[NAV] raw_body_len=");
        crate::sys::serial::print_dec(body.len() as u64);
        crate::sys::serial::println(b"");
        let result = crate::apps::ecosystem::browser::navigate::decompress::decompress_body(&body, enc.as_deref());
        crate::sys::serial::print(b"[NAV] decompressed_len=");
        crate::sys::serial::print_dec(result.len() as u64);
        crate::sys::serial::println(b"");
        result
    } else { Vec::from(data) }
}

fn decode_chunked(mut data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let crlf = match data.windows(2).position(|w| w == b"\r\n") { Some(pos) => pos, None => break };
        let size_str = match core::str::from_utf8(&data[..crlf]) { Ok(s) => s.split(';').next().unwrap_or("").trim(), Err(_) => break };
        let chunk_len = match usize::from_str_radix(size_str, 16) { Ok(n) => n, Err(_) => break };
        if chunk_len == 0 { break; }
        let chunk_start = crlf + 2;
        let chunk_end = chunk_start + chunk_len;
        if chunk_end > data.len() { output.extend_from_slice(&data[chunk_start..]); break; }
        output.extend_from_slice(&data[chunk_start..chunk_end]);
        let next = chunk_end + 2;
        if next > data.len() { break; }
        data = &data[next..];
    }
    output
}

pub fn extract_title(body: &[u8]) -> Option<String> {
    let html = core::str::from_utf8(body).ok()?;
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start..].find("</title>")?;
    let title = &html[start + 7..start + end];
    Some(String::from(title.trim()))
}
