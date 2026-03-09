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
use miniz_oxide::inflate::{decompress_to_vec_zlib, decompress_to_vec};

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
    /// Create a new empty HttpResponse
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

    /// Get a header value by name (case-insensitive)
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        for (k, v) in &self.headers {
            if k.to_ascii_lowercase() == name_lower {
                return Some(v.as_str());
            }
        }
        None
    }

    /// Get the Content-Length header value as a number
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    /// Get the Content-Type header value
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Get the Location header value (for redirects)
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    /// Check if the response is a redirect (3xx status)
    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    pub fn get_set_cookie_headers(&self) -> Vec<&str> {
        self.headers.iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == "set-cookie")
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn is_keep_alive(&self) -> bool {
        if let Some(conn) = self.header("connection") {
            conn.to_ascii_lowercase().contains("keep-alive")
        } else {
            false
        }
    }

    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }
}

pub(super) fn parse_response(data: &[u8]) -> Result<HttpResponse, &'static str> {
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

    let body = if is_chunked {
        decode_chunked_body(raw_body)?
    } else {
        raw_body.to_vec()
    };

    /*
     * decompress gzip/deflate content-encoding. most websites use
     * compression so this is essential for the browser.
     */
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

pub(super) fn find_sequence(data: &[u8], seq: &[u8]) -> Option<usize> {
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

/*
 * decompress gzip or deflate encoded content.
 * gzip has a 10-byte header we need to skip before deflate data.
 */
fn decompress_content_encoding(body: &[u8], encoding: Option<&str>) -> Vec<u8> {
    match encoding {
        Some("gzip") | Some("x-gzip") => decompress_gzip(body).unwrap_or_else(|| body.to_vec()),
        Some("deflate") => decompress_deflate(body).unwrap_or_else(|| body.to_vec()),
        _ => body.to_vec(),
    }
}

fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
    /*
     * gzip format: 10-byte header + compressed data + 8-byte trailer
     * header: 1F 8B 08 [flags] [mtime 4b] [xfl] [os]
     * we need to skip header (and optional extra fields) to get deflate data.
     */
    if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B {
        return None;
    }

    let flags = data[3];
    let mut offset = 10;

    /* skip optional extra field (FEXTRA flag = 0x04) */
    if flags & 0x04 != 0 && offset + 2 <= data.len() {
        let extra_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + extra_len;
    }

    /* skip optional filename (FNAME flag = 0x08) */
    if flags & 0x08 != 0 {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }

    /* skip optional comment (FCOMMENT flag = 0x10) */
    if flags & 0x10 != 0 {
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }

    /* skip optional header CRC (FHCRC flag = 0x02) */
    if flags & 0x02 != 0 {
        offset += 2;
    }

    if offset >= data.len().saturating_sub(8) {
        return None;
    }

    /* deflate data ends 8 bytes before the end (CRC32 + ISIZE) */
    let deflate_data = &data[offset..data.len().saturating_sub(8)];

    decompress_to_vec(deflate_data).ok()
}

fn decompress_deflate(data: &[u8]) -> Option<Vec<u8>> {
    /*
     * deflate can be raw deflate or zlib-wrapped.
     * try zlib first (has header), then raw deflate.
     */
    if data.len() >= 2 {
        let cmf = data[0];
        let flg = data[1];
        /* zlib header check: (CMF * 256 + FLG) % 31 == 0 */
        if (cmf as u16 * 256 + flg as u16) % 31 == 0 {
            if let Ok(decompressed) = decompress_to_vec_zlib(data) {
                return Some(decompressed);
            }
        }
    }

    /* try raw deflate */
    decompress_to_vec(data).ok()
}
