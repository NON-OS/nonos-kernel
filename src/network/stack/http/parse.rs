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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::types::{HttpError, HttpResponse};
use super::super::util::find_subsequence;

pub(super) fn parse_url(url: &str) -> Option<(String, u16, String, bool)> {
    let is_https = url.starts_with("https://");
    let url = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    let (host_port, path) = url.find('/').map_or((url, "/"), |i| (&url[..i], &url[i..]));
    let default_port = if is_https { 443 } else { 80 };
    let (host, port) = if let Some(i) = host_port.rfind(':') {
        (&host_port[..i], host_port[i+1..].parse().ok()?)
    } else {
        (host_port, default_port)
    };
    Some((String::from(host), port, String::from(path), is_https))
}

pub(super) fn resolve_host(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 {
        if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
            parts[0].parse::<u8>(),
            parts[1].parse::<u8>(),
            parts[2].parse::<u8>(),
            parts[3].parse::<u8>(),
        ) {
            return Some([a, b, c, d]);
        }
    }
    crate::network::dns::resolve_v4(host).ok()
}

pub(super) fn parse_response(data: &[u8]) -> Result<HttpResponse, HttpError> {
    let header_end = find_subsequence(data, b"\r\n\r\n").ok_or(HttpError::InvalidResponse)?;
    let header_bytes = &data[..header_end];
    let body = data[header_end + 4..].to_vec();

    let header_str = core::str::from_utf8(header_bytes).map_err(|_| HttpError::InvalidResponse)?;
    let mut lines = header_str.lines();

    let status_line = lines.next().ok_or(HttpError::InvalidResponse)?;
    let status_code = status_line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError::InvalidResponse)?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some(i) = line.find(':') {
            let key = line[..i].trim().to_lowercase();
            let value = String::from(line[i+1..].trim());
            headers.insert(key, value);
        }
    }

    Ok(HttpResponse { status_code, headers, body })
}
