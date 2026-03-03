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

use super::parse::{parse_response, parse_url, resolve_host};
use super::types::{HttpError, HttpResponse};

pub fn get(url: &str, headers: &[(&str, &str)], timeout_ms: u32) -> Result<HttpResponse, HttpError> {
    request("GET", url, None, headers, timeout_ms)
}

pub fn post(url: &str, body: &[u8], headers: &[(&str, &str)], timeout_ms: u32) -> Result<HttpResponse, HttpError> {
    request("POST", url, Some(body), headers, timeout_ms)
}

pub fn put(url: &str, body: &[u8], headers: &[(&str, &str)], timeout_ms: u32) -> Result<HttpResponse, HttpError> {
    request("PUT", url, Some(body), headers, timeout_ms)
}

pub fn delete(url: &str, headers: &[(&str, &str)], timeout_ms: u32) -> Result<HttpResponse, HttpError> {
    request("DELETE", url, None, headers, timeout_ms)
}

pub fn head(url: &str, headers: &[(&str, &str)], timeout_ms: u32) -> Result<HttpResponse, HttpError> {
    request("HEAD", url, None, headers, timeout_ms)
}

fn request(method: &str, url: &str, body: Option<&[u8]>, headers: &[(&str, &str)], timeout_ms: u32) -> Result<HttpResponse, HttpError> {
    let (host, port, path, is_https) = parse_url(url).ok_or(HttpError::InvalidUrl)?;

    let addr = resolve_host(&host).ok_or(HttpError::DnsError)?;

    let mut request = alloc::format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);
    for (key, value) in headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(b) = body {
        request.push_str(&alloc::format!("Content-Length: {}\r\n", b.len()));
    }
    request.push_str("Connection: close\r\n\r\n");

    let mut req_bytes = request.into_bytes();
    if let Some(b) = body {
        req_bytes.extend_from_slice(b);
    }

    let stack = super::super::get_network_stack().ok_or(HttpError::NetworkError)?;

    let response_bytes = if is_https {
        stack.https_request(addr, port, &host, &req_bytes, timeout_ms)
            .map_err(|_| HttpError::TlsError)?
    } else {
        stack.http_request(addr, port, &req_bytes)
            .map_err(|_| HttpError::NetworkError)?
    };

    parse_response(&response_bytes)
}
