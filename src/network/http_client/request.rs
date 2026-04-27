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

use super::url::{ParsedUrl, DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) const HTTP_TIMEOUT_MS: u64 = 30_000;
pub(super) const MAX_REDIRECTS: u8 = 10;
pub(super) const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
pub(super) const USER_AGENT: &[u8] = b"NONOS-HTTP/1.0";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Head => "HEAD",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

#[derive(Clone)]
pub struct HttpRequestOptions {
    pub method: HttpMethod,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub follow_redirects: bool,
    pub max_redirects: u8,
    pub timeout_ms: u64,
    pub verbose: bool,
    pub keep_alive: bool,
    pub use_cookies: bool,
}

impl Default for HttpRequestOptions {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            headers: Vec::new(),
            body: None,
            follow_redirects: true,
            max_redirects: MAX_REDIRECTS,
            timeout_ms: HTTP_TIMEOUT_MS,
            verbose: false,
            keep_alive: true,
            use_cookies: true,
        }
    }
}

pub(super) fn build_request(
    url: &ParsedUrl,
    method: HttpMethod,
    body: Option<&[u8]>,
    options: &HttpRequestOptions,
) -> Vec<u8> {
    let mut request = Vec::new();

    request.extend_from_slice(method.as_str().as_bytes());
    request.push(b' ');
    request.extend_from_slice(url.path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\n");

    request.extend_from_slice(b"Host: ");
    request.extend_from_slice(url.host.as_bytes());
    if url.port != DEFAULT_HTTP_PORT && url.port != DEFAULT_HTTPS_PORT {
        request.push(b':');
        request.extend_from_slice(format!("{}", url.port).as_bytes());
    }
    request.extend_from_slice(b"\r\n");

    request.extend_from_slice(b"User-Agent: ");
    request.extend_from_slice(USER_AGENT);
    request.extend_from_slice(b"\r\n");

    if options.keep_alive {
        request.extend_from_slice(b"Connection: keep-alive\r\n");
    } else {
        request.extend_from_slice(b"Connection: close\r\n");
    }

    request.extend_from_slice(b"Accept: */*\r\n");
    #[cfg(feature = "nonos-brotli")]
    request.extend_from_slice(b"Accept-Encoding: gzip, deflate, br\r\n");
    #[cfg(not(feature = "nonos-brotli"))]
    request.extend_from_slice(b"Accept-Encoding: gzip, deflate\r\n");

    if options.use_cookies {
        let jar = super::cookies::get_cookie_jar().lock();
        if let Some(cookie_header) = jar.build_cookie_header(&url.host, &url.path, url.is_https) {
            request.extend_from_slice(b"Cookie: ");
            request.extend_from_slice(cookie_header.as_bytes());
            request.extend_from_slice(b"\r\n");
        }
    }

    for (name, value) in &options.headers {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }

    if let Some(body_data) = body {
        request.extend_from_slice(b"Content-Length: ");
        request.extend_from_slice(format!("{}", body_data.len()).as_bytes());
        request.extend_from_slice(b"\r\n");
    }

    request.extend_from_slice(b"\r\n");

    if let Some(body_data) = body {
        request.extend_from_slice(body_data);
    }

    request
}
