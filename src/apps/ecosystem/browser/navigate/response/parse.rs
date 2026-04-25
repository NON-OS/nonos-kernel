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

const MAX_CONTENT_LENGTH: usize = 16 * 1024 * 1024;

pub(crate) fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

pub(crate) fn is_response_complete(data: &[u8]) -> bool {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let body_start = header_end + 4;
        let body_len = data.len() - body_start;
        if let Some(cl) = parse_content_length(headers) {
            return body_len >= cl;
        }
        if is_chunked_transfer(headers) {
            return data.len() >= 5 && data[data.len() - 5..] == *b"0\r\n\r\n";
        }
    }
    false
}

pub(super) fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let val = line[15..].trim();
            let len: usize = val.parse().ok()?;
            if len > MAX_CONTENT_LENGTH {
                return None;
            }
            return Some(len);
        }
    }
    None
}

pub(super) fn is_chunked_transfer(headers: &[u8]) -> bool {
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
