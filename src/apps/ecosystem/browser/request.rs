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

//! HTTP request handling for browser.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::state::{get_settings, ProxyMode};
use crate::apps::ecosystem::privacy::{should_block_request, strip_tracking_params};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    NetworkError,
    DnsError,
    TlsError,
    Timeout,
    InvalidUrl,
    Blocked,
    TooManyRedirects,
    ConnectionRefused,
    InvalidResponse,
    HttpsRequired,
}

#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub method: HttpMethod,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u32,
    pub follow_redirects: bool,
    pub max_redirects: u8,
    pub verify_ssl: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            headers: BTreeMap::new(),
            body: None,
            timeout_ms: 30000,
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FetchResult {
    pub status_code: u16,
    pub status_text: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub final_url: String,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub title: Option<String>,
}

impl FetchResult {
    pub fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }

    pub fn is_redirect(&self) -> bool {
        self.status_code >= 300 && self.status_code < 400
    }

    pub fn is_client_error(&self) -> bool {
        self.status_code >= 400 && self.status_code < 500
    }

    pub fn is_server_error(&self) -> bool {
        self.status_code >= 500
    }

    pub fn body_as_string(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    pub fn redirect_url(&self) -> Option<&String> {
        self.headers.get("location")
    }
}

pub fn fetch_page(url: &str, options: FetchOptions) -> Result<FetchResult, FetchError> {
    let settings = get_settings();

    let url = strip_tracking_params(url);

    if settings.https_only && url.starts_with("http://") {
        return Err(FetchError::HttpsRequired);
    }

    let domain = extract_domain(&url).ok_or(FetchError::InvalidUrl)?;

    if settings.tracking_protection && should_block_request(&domain).0 {
        return Err(FetchError::Blocked);
    }

    let mut request_headers = build_headers(&url, &settings);
    for (key, value) in options.headers.iter() {
        request_headers.insert(key.clone(), value.clone());
    }

    let result = match settings.proxy.mode {
        ProxyMode::None => direct_fetch(&url, &options, &request_headers),
        ProxyMode::Onion => onion_fetch(&url, &options, &request_headers),
        ProxyMode::Custom => proxy_fetch(&url, &options, &request_headers, &settings.proxy.host, settings.proxy.port),
        ProxyMode::System => direct_fetch(&url, &options, &request_headers),
    }?;

    if options.follow_redirects && result.is_redirect() {
        if let Some(redirect_url) = result.redirect_url() {
            let resolved_url = resolve_url(&url, redirect_url);
            let mut new_options = options.clone();
            new_options.max_redirects = options.max_redirects.saturating_sub(1);

            if new_options.max_redirects == 0 {
                return Err(FetchError::TooManyRedirects);
            }

            return fetch_page(&resolved_url, new_options);
        }
    }

    Ok(result)
}

fn direct_fetch(
    url: &str,
    options: &FetchOptions,
    headers: &BTreeMap<String, String>,
) -> Result<FetchResult, FetchError> {
    use crate::network::http;

    let header_vec: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let response = match options.method {
        HttpMethod::Get => http::get(url, &header_vec, options.timeout_ms),
        HttpMethod::Post => {
            let body = options.body.as_deref().unwrap_or(&[]);
            http::post(url, body, &header_vec, options.timeout_ms)
        }
        HttpMethod::Put => {
            let body = options.body.as_deref().unwrap_or(&[]);
            http::put(url, body, &header_vec, options.timeout_ms)
        }
        HttpMethod::Delete => http::delete(url, &header_vec, options.timeout_ms),
        HttpMethod::Head => http::head(url, &header_vec, options.timeout_ms),
        _ => http::get(url, &header_vec, options.timeout_ms),
    }
    .map_err(|e| match e {
        http::HttpError::DnsError => FetchError::DnsError,
        http::HttpError::TlsError => FetchError::TlsError,
        http::HttpError::Timeout => FetchError::Timeout,
        http::HttpError::ConnectionRefused => FetchError::ConnectionRefused,
        _ => FetchError::NetworkError,
    })?;

    let mut response_headers = BTreeMap::new();
    for (key, value) in response.headers.iter() {
        response_headers.insert(key.to_lowercase(), value.clone());
    }

    let content_type = response_headers.get("content-type").cloned();
    let content_length = response_headers
        .get("content-length")
        .and_then(|s| s.parse().ok());

    Ok(FetchResult {
        status_code: response.status_code,
        status_text: status_text(response.status_code),
        headers: response_headers,
        body: response.body,
        final_url: String::from(url),
        content_type,
        content_length,
        title: None,
    })
}

fn onion_fetch(
    url: &str,
    options: &FetchOptions,
    headers: &BTreeMap<String, String>,
) -> Result<FetchResult, FetchError> {
    use crate::network::socks;

    let proxy_conn = socks::connect("127.0.0.1", 9050, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let (host, port, path) = parse_url(url).ok_or(FetchError::InvalidUrl)?;

    socks::connect_target(&proxy_conn, &host, port, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let request = build_http_request(options.method.as_str(), &host, &path, headers, options.body.as_deref());
    socks::send(&proxy_conn, &request).map_err(|_| FetchError::NetworkError)?;

    let response_data = socks::recv(&proxy_conn, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    parse_http_response(&response_data, url)
}

fn proxy_fetch(
    url: &str,
    options: &FetchOptions,
    headers: &BTreeMap<String, String>,
    proxy_host: &str,
    proxy_port: u16,
) -> Result<FetchResult, FetchError> {
    use crate::network::socks;

    let proxy_conn = socks::connect(proxy_host, proxy_port, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let (host, port, path) = parse_url(url).ok_or(FetchError::InvalidUrl)?;

    socks::connect_target(&proxy_conn, &host, port, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let request = build_http_request(options.method.as_str(), &host, &path, headers, options.body.as_deref());
    socks::send(&proxy_conn, &request).map_err(|_| FetchError::NetworkError)?;

    let response_data = socks::recv(&proxy_conn, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    parse_http_response(&response_data, url)
}

fn build_headers(url: &str, settings: &super::state::BrowserSettings) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();

    headers.insert(String::from("user-agent"), settings.user_agent.clone());
    headers.insert(String::from("accept"), String::from("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
    headers.insert(String::from("accept-language"), String::from("en-US,en;q=0.5"));
    headers.insert(String::from("accept-encoding"), String::from("gzip, deflate"));
    headers.insert(String::from("connection"), String::from("keep-alive"));

    if settings.do_not_track {
        headers.insert(String::from("dnt"), String::from("1"));
        headers.insert(String::from("sec-gpc"), String::from("1"));
    }

    match settings.referrer_policy {
        super::state::ReferrerPolicy::NoReferrer => {}
        _ => {
            if let Some(domain) = extract_domain(url) {
                headers.insert(String::from("referer"), alloc::format!("https://{}/", domain));
            }
        }
    }

    headers
}

fn build_http_request(
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

fn parse_http_response(data: &[u8], url: &str) -> Result<FetchResult, FetchError> {
    let response_str = core::str::from_utf8(data).map_err(|_| FetchError::InvalidResponse)?;

    let header_end = response_str
        .find("\r\n\r\n")
        .ok_or(FetchError::InvalidResponse)?;

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
    let content_length = headers
        .get("content-length")
        .and_then(|s| s.parse().ok());

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

fn extract_domain(url: &str) -> Option<String> {
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

    let host = if let Some(at_pos) = host.find('@') {
        &host[at_pos + 1..]
    } else {
        host
    };

    let host = if let Some(colon_pos) = host.find(':') {
        &host[..colon_pos]
    } else {
        host
    };

    Some(String::from(host))
}

fn parse_url(url: &str) -> Option<(String, u16, String)> {
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

fn resolve_url(base: &str, relative: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return String::from(relative);
    }

    if relative.starts_with("//") {
        let scheme = if base.starts_with("https://") {
            "https:"
        } else {
            "http:"
        };
        return alloc::format!("{}{}", scheme, relative);
    }

    if relative.starts_with('/') {
        if let Some(domain) = extract_domain(base) {
            let scheme = if base.starts_with("https://") {
                "https://"
            } else {
                "http://"
            };
            return alloc::format!("{}{}{}", scheme, domain, relative);
        }
    }

    let last_slash = base.rfind('/').unwrap_or(base.len());
    let base_dir = &base[..last_slash + 1];
    alloc::format!("{}{}", base_dir, relative)
}

fn status_text(code: u16) -> String {
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
