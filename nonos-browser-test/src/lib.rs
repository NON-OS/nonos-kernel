// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Host-side E2E coverage for browser navigation pure logic.
// Mirrors src/apps/ecosystem/browser/navigate/{url.rs, api.rs, response/parse.rs}
// error-mapping; kept in sync manually (both files are tiny and stable).

pub struct UrlParts {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub is_https: bool,
}

pub fn parse_url(url: &str) -> Option<UrlParts> {
    let (is_https, rest) = if url.starts_with("https://") {
        (true, &url[8..])
    } else if url.starts_with("http://") {
        (false, &url[7..])
    } else {
        (true, url)
    };

    let default_port: u16 = if is_https { 443 } else { 80 };

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

    if host.is_empty() {
        return None;
    }

    Some(UrlParts {
        host: host.to_string(),
        port,
        path: path.to_string(),
        is_https,
    })
}

pub fn map_nav_error(e: &str) -> &str {
    match e {
        "dns timeout" => "DNS resolution timed out",
        "no dns records" => "Domain not found",
        "http timeout" => "Request timed out",
        "no network" => "No network connection",
        "network not ready" => "Network not ready (waiting for DHCP)",
        "no network stack" => "Network not ready (waiting for DHCP)",
        "no ipv4 address" => "Network not ready (waiting for DHCP)",
        "no routable ip" => "Network not ready (waiting for DHCP)",
        "dns query already in progress" => "DNS busy, retry",
        "dns bind failed" => "DNS socket error",
        "dns send failed" => "DNS send failed (network down)",
        "TLS handshake failed" => "TLS/SSL error",
        "TCP connect failed" => "Connection refused",
        other => other,
    }
}

pub fn response_complete(data: &[u8]) -> bool {
    let header_end = match find_header_end(data) { Some(end) => end, None => return false };
    let headers = &data[..header_end];
    let body_start = header_end + 4;
    if has_chunked_header(headers) { return chunked_body_complete(&data[body_start..]); }
    false
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    for pos in 0..data.len().saturating_sub(3) {
        if &data[pos..pos + 4] == b"\r\n\r\n" { return Some(pos); }
    }
    None
}

fn has_chunked_header(headers: &[u8]) -> bool {
    let text = core::str::from_utf8(headers).ok().unwrap_or("");
    text.lines().any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:") && line.to_ascii_lowercase().contains("chunked"))
}

fn chunked_body_complete(body: &[u8]) -> bool {
    let mut pos = 0;
    while pos < body.len() {
        let line_end = match find_crlf(body, pos) { Some(end) => end, None => return false };
        let size_text = core::str::from_utf8(&body[pos..line_end]).ok().unwrap_or("0");
        let size_part = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_part, 16).ok().unwrap_or(0);
        let chunk_start = line_end + 2;
        if size == 0 { return trailers_complete(body, chunk_start); }
        let chunk_end = match chunk_start.checked_add(size) { Some(end) => end, None => return false };
        if body.len() < chunk_end + 2 || &body[chunk_end..chunk_end + 2] != b"\r\n" { return false; }
        pos = chunk_end + 2;
    }
    false
}

fn trailers_complete(body: &[u8], start: usize) -> bool {
    if body.len() >= start + 2 && &body[start..start + 2] == b"\r\n" { return true; }
    for pos in start..body.len().saturating_sub(3) {
        if &body[pos..pos + 4] == b"\r\n\r\n" { return true; }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_url_returns_none() {
        assert!(parse_url("://broken").is_none());
    }

    #[test]
    fn http_url_parses_defaults() {
        let p = parse_url("http://example.com/").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/");
        assert!(!p.is_https);
    }

    #[test]
    fn https_url_parses_defaults() {
        let p = parse_url("https://google.com/search?q=1").unwrap();
        assert_eq!(p.host, "google.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.path, "/search?q=1");
        assert!(p.is_https);
    }

    #[test]
    fn bare_host_defaults_to_https() {
        let p = parse_url("google.com").unwrap();
        assert_eq!(p.host, "google.com");
        assert_eq!(p.port, 443);
        assert!(p.is_https);
    }

    #[test]
    fn dhcp_not_ready_strings_all_map_to_friendly() {
        let want = "Network not ready (waiting for DHCP)";
        assert_eq!(map_nav_error("network not ready"), want);
        assert_eq!(map_nav_error("no network stack"), want);
        assert_eq!(map_nav_error("no ipv4 address"), want);
        assert_eq!(map_nav_error("no routable ip"), want);
    }

    #[test]
    fn dns_timeout_maps_to_friendly() {
        assert_eq!(map_nav_error("dns timeout"), "DNS resolution timed out");
    }

    #[test]
    fn unknown_error_passes_through() {
        assert_eq!(map_nav_error("nope"), "nope");
    }

    #[test]
    fn chunked_response_allows_trailers() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nX-Debug: 1\r\n\r\n";
        assert!(response_complete(response));
    }

    #[test]
    fn chunked_response_waits_for_trailer_end() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nX-Debug: 1\r\n";
        assert!(!response_complete(response));
    }
}
