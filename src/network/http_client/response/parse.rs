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

use super::chunked::decode_chunked_body;
use super::decompress::decompress_content_encoding;
use super::helpers::{find_sequence, parse_status_code, trim_crlf};
use super::types::HttpResponse;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub(crate) fn parse_response(data: &[u8]) -> Result<HttpResponse, &'static str> {
    let header_end = find_sequence(data, b"\r\n\r\n").ok_or("malformed response")?;
    let headers_raw = &data[..header_end];
    let raw_body = &data[header_end + 4..];
    let status_end = find_sequence(headers_raw, b"\r\n").ok_or("no status line")?;
    let status_line = &headers_raw[..status_end];
    let status_parts: Vec<&[u8]> = status_line.splitn(3, |&b| b == b' ').collect();
    if status_parts.len() < 2 {
        return Err("malformed status line");
    }
    let status_code = parse_status_code(status_parts[1])?;
    let status_text = if status_parts.len() > 2 {
        String::from_utf8_lossy(status_parts[2]).into_owned()
    } else {
        String::new()
    };
    let mut headers = Vec::new();
    let mut is_chunked = false;
    let mut content_encoding: Option<String> = None;
    let header_lines = &headers_raw[status_end + 2..];
    for line in header_lines.split(|&b| b == b'\n') {
        let line = trim_crlf(line);
        if line.is_empty() {
            continue;
        }
        if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon_pos]).trim().to_string();
            let value = String::from_utf8_lossy(&line[colon_pos + 1..]).trim().to_string();
            let name_lower = name.to_ascii_lowercase();
            if name_lower == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
            if name_lower == "content-encoding" {
                content_encoding = Some(value.to_ascii_lowercase());
            }
            headers.push((name, value));
        }
    }
    let body = if is_chunked { decode_chunked_body(raw_body)? } else { raw_body.to_vec() };
    let body = decompress_content_encoding(&body, content_encoding.as_deref());
    Ok(HttpResponse {
        status_code,
        status_text,
        headers,
        body,
        final_url: String::new(),
        redirects: 0,
    })
}
