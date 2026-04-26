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
        if &data[i..i + 4] == b"\r\n\r\n" { return Some(i); }
    }
    None
}

pub(crate) fn is_response_complete(data: &[u8]) -> bool {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let body_start = header_end + 4;
        let body_len = data.len() - body_start;
        if let Some(cl) = parse_content_length(headers) { return body_len >= cl; }
        if is_chunked_transfer(headers) { return is_chunked_body_complete(&data[body_start..]); }
    }
    false
}

fn is_chunked_body_complete(body: &[u8]) -> bool {
    let mut pos = 0;
    while pos < body.len() {
        let line_end = match find_crlf(body, pos) { Some(end) => end, None => return false };
        let size = match parse_chunk_size(&body[pos..line_end]) { Some(size) => size, None => return false };
        let chunk_start = line_end + 2;
        if size == 0 { return has_complete_trailers(body, chunk_start); }
        let chunk_end = match chunk_start.checked_add(size) { Some(end) => end, None => return false };
        if body.len() < chunk_end + 2 { return false; }
        if &body[chunk_end..chunk_end + 2] != b"\r\n" { return false; }
        pos = chunk_end + 2;
    }
    false
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let size_end = line.iter().position(|byte| *byte == b';').unwrap_or(line.len());
    let size_text = core::str::from_utf8(&line[..size_end]).ok()?.trim();
    usize::from_str_radix(size_text, 16).ok()
}

fn has_complete_trailers(body: &[u8], start: usize) -> bool {
    if body.len() >= start + 2 && &body[start..start + 2] == b"\r\n" { return true; }
    let mut pos = start;
    while pos + 3 < body.len() {
        if &body[pos..pos + 4] == b"\r\n\r\n" { return true; }
        pos += 1;
    }
    false
}

fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    while pos + 1 < data.len() {
        if data[pos] == b'\r' && data[pos + 1] == b'\n' { return Some(pos); }
        pos += 1;
    }
    None
}

pub(super) fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let val = line[15..].trim();
            let len: usize = val.parse().ok()?;
            if len > MAX_CONTENT_LENGTH { return None; }
            return Some(len);
        }
    }
    None
}

pub(super) fn is_chunked_transfer(headers: &[u8]) -> bool {
    let s = match core::str::from_utf8(headers) { Ok(s) => s, Err(_) => return false };
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") { return lower[18..].trim().contains("chunked"); }
    }
    false
}
