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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub final_url: String,
    pub redirects: u8,
}

impl HttpResponse {
    pub fn new() -> Self {
        Self {
            status_code: 0,
            status_text: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            final_url: String::new(),
            redirects: 0,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        for (k, v) in &self.headers {
            if k.to_ascii_lowercase() == name_lower {
                return Some(v.as_str());
            }
        }
        None
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }
}

pub fn parse_response(data: &[u8]) -> Result<HttpResponse, &'static str> {
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
    let header_lines = &headers_raw[status_end + 2..];

    for line in header_lines.split(|&b| b == b'\n') {
        let line = trim_crlf(line);
        if line.is_empty() {
            continue;
        }

        if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon_pos]).trim().to_string();
            let value = String::from_utf8_lossy(&line[colon_pos + 1..]).trim().to_string();

            if name.to_ascii_lowercase() == "transfer-encoding" &&
               value.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }

            headers.push((name, value));
        }
    }

    let body = if is_chunked {
        decode_chunked_body(raw_body)?
    } else {
        raw_body.to_vec()
    };

    Ok(HttpResponse {
        status_code,
        status_text,
        headers,
        body,
        final_url: String::new(),
        redirects: 0,
    })
}

fn decode_chunked_body(data: &[u8]) -> Result<Vec<u8>, &'static str> {
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
    let hex_part = if let Some(idx) = data.iter().position(|&b| b == b';') {
        &data[..idx]
    } else {
        data
    };

    let hex_trimmed: Vec<u8> = hex_part.iter()
        .copied()
        .skip_while(|&b| b == b' ' || b == b'\t')
        .collect();

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
        size = size.checked_mul(16).ok_or("chunk size overflow")?
            .checked_add(digit as usize).ok_or("chunk size overflow")?;
    }

    Ok(size)
}

pub fn find_sequence(data: &[u8], seq: &[u8]) -> Option<usize> {
    data.windows(seq.len()).position(|w| w == seq)
}

fn parse_status_code(data: &[u8]) -> Result<u16, &'static str> {
    if data.len() < 3 {
        return Err("invalid status code");
    }

    let mut code: u16 = 0;
    for &b in data.iter().take(3) {
        if !b.is_ascii_digit() {
            return Err("invalid status code");
        }
        code = code * 10 + (b - b'0') as u16;
    }

    Ok(code)
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r") {
        &line[..line.len() - 1]
    } else {
        line
    }
}
