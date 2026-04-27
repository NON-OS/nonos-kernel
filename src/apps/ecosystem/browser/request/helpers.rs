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

use super::types::{FetchError, FetchResult};
use crate::apps::ecosystem::browser::state::BrowserSettings;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub(super) fn build_headers(url: &str, settings: &BrowserSettings) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();

    headers.insert(String::from("user-agent"), settings.user_agent.clone());
    headers.insert(
        String::from("accept"),
        String::from("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(String::from("accept-language"), String::from("en-US,en;q=0.5"));
    headers.insert(String::from("accept-encoding"), String::from("gzip, deflate"));
    headers.insert(String::from("connection"), String::from("keep-alive"));

    if settings.do_not_track {
        headers.insert(String::from("dnt"), String::from("1"));
        headers.insert(String::from("sec-gpc"), String::from("1"));
    }

    match settings.referrer_policy {
        crate::apps::ecosystem::browser::state::ReferrerPolicy::NoReferrer => {}
        _ => {
            if let Some(domain) = extract_domain(url) {
                headers.insert(String::from("referer"), alloc::format!("https://{}/", domain));
            }
        }
    }

    headers
}

pub(super) fn build_http_request(
    method: &str,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut request = alloc::format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, host);

    for (key, value) in headers {
        request.push_str(&alloc::format!("{}: {}\r\n", key, value));
    }

    if let Some(body) = body {
        request.push_str(&alloc::format!("Content-Length: {}\r\n", body.len()));
    }

    request.push_str("\r\n");

    let mut bytes = request.into_bytes();
    if let Some(body) = body {
        bytes.extend_from_slice(body);
    }

    bytes
}

pub(super) fn parse_http_response(data: &[u8], url: &str) -> Result<FetchResult, FetchError> {
    let response_str = core::str::from_utf8(data).map_err(|_| FetchError::InvalidResponse)?;

    let header_end = response_str.find("\r\n\r\n").ok_or(FetchError::InvalidResponse)?;

    let header_part = &response_str[..header_end];
    let body_part = &data[header_end + 4..];

    let mut lines = header_part.lines();
    let status_line = lines.next().ok_or(FetchError::InvalidResponse)?;

    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(FetchError::InvalidResponse);
    }

    let status_code: u16 = parts[1].parse().map_err(|_| FetchError::InvalidResponse)?;
    let status_text_str = parts.get(2).unwrap_or(&"");

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    let content_type = headers.get("content-type").cloned();
    let content_length = headers.get("content-length").and_then(|s| s.parse().ok());

    Ok(FetchResult {
        status_code,
        status_text: String::from(*status_text_str),
        headers,
        body: body_part.to_vec(),
        final_url: String::from(url),
        content_type,
        content_length,
        title: None,
    })
}

pub(super) fn extract_domain(url: &str) -> Option<String> {
    let start = if url.starts_with("https://") {
        8
    } else if url.starts_with("http://") {
        7
    } else {
        return None;
    };

    let rest = &url[start..];
    let end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..end];

    let host = if let Some(at_pos) = host.find('@') { &host[at_pos + 1..] } else { host };

    let host = if let Some(colon_pos) = host.find(':') { &host[..colon_pos] } else { host };

    Some(String::from(host))
}

pub(super) fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let (scheme, rest) = if url.starts_with("https://") {
        ("https", &url[8..])
    } else if url.starts_with("http://") {
        ("http", &url[7..])
    } else {
        return None;
    };

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(pos) => {
            let h = &host_port[..pos];
            let p: u16 = host_port[pos + 1..].parse().ok()?;
            (h, p)
        }
        None => (host_port, default_port),
    };

    Some((String::from(host), port, String::from(path)))
}

pub(super) fn resolve_url(base: &str, relative: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return String::from(relative);
    }

    if relative.starts_with("//") {
        let scheme = if base.starts_with("https://") { "https:" } else { "http:" };
        return alloc::format!("{}{}", scheme, relative);
    }

    if relative.starts_with('/') {
        if let Some(domain) = extract_domain(base) {
            let scheme = if base.starts_with("https://") { "https://" } else { "http://" };
            return alloc::format!("{}{}{}", scheme, domain, relative);
        }
    }

    let last_slash = base.rfind('/').unwrap_or(base.len());
    let base_dir = &base[..last_slash + 1];
    alloc::format!("{}{}", base_dir, relative)
}

pub(super) fn status_text(code: u16) -> String {
    String::from(match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    })
}
