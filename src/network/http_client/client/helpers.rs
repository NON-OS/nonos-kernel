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

use crate::network::http_client::response::find_sequence;

pub(super) fn is_response_complete(data: &[u8], header_end: usize) -> bool {
    let headers = &data[..header_end];
    let body = &data[header_end + 4..];
    if let Some(content_length) = parse_content_length(headers) {
        return body.len() >= content_length;
    }
    if has_chunked_encoding(headers) {
        return find_chunked_terminator(body);
    }
    false
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let header_str = core::str::from_utf8(headers).ok()?;
    for line in header_str.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let value = line[15..].trim();
            return value.parse().ok();
        }
    }
    None
}

fn has_chunked_encoding(headers: &[u8]) -> bool {
    let header_str = match core::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in header_str.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            return true;
        }
    }
    false
}

fn find_chunked_terminator(body: &[u8]) -> bool {
    if body.len() < 5 {
        return false;
    }
    let mut i = 0;
    while i + 5 <= body.len() {
        if body[i] == b'0' && body[i + 1] == b'\r' && body[i + 2] == b'\n' {
            if body[i + 3] == b'\r' && body[i + 4] == b'\n' {
                return true;
            }
            if find_sequence(&body[i + 3..], b"\r\n\r\n").is_some() {
                return true;
            }
        }
        if let Some(pos) = find_sequence(&body[i..], b"\r\n") {
            i += pos + 2;
        } else {
            break;
        }
    }
    false
}
