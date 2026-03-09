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

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::format;
use super::url::{ParsedUrl, resolve_host};
use super::response::{HttpResponse, parse_response, find_sequence};
use super::request::{HttpMethod, HttpRequestOptions, build_request, MAX_RESPONSE_SIZE};
use super::tls_util::wrap_tls_record;
use crate::network::onion::tls::TLSConnection;

pub struct HttpClient {
    options: HttpRequestOptions,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            options: HttpRequestOptions::default(),
        }
    }

    pub fn with_options(options: HttpRequestOptions) -> Self {
        Self { options }
    }

    pub fn get(&self, url: &str) -> Result<HttpResponse, &'static str> {
        self.request(url, HttpMethod::Get, None)
    }

    pub fn head(&self, url: &str) -> Result<HttpResponse, &'static str> {
        self.request(url, HttpMethod::Head, None)
    }

    pub fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, &'static str> {
        self.request(url, HttpMethod::Post, Some(body))
    }

    pub fn request(&self, url: &str, method: HttpMethod, body: Option<&[u8]>) -> Result<HttpResponse, &'static str> {
        let mut current_url = url.to_string();
        let mut redirects = 0u8;

        loop {
            let parsed = ParsedUrl::parse(&current_url)?;

            let response = if parsed.is_https {
                self.do_https_request(&parsed, method, body)?
            } else {
                self.do_request(&parsed, method, body)?
            };

            if response.is_redirect() && self.options.follow_redirects {
                if redirects >= self.options.max_redirects {
                    return Err("too many redirects");
                }

                if self.options.use_cookies {
                    let mut jar = super::cookies::get_cookie_jar().lock();
                    for set_cookie in response.get_set_cookie_headers() {
                        jar.parse_set_cookie(set_cookie, &parsed.host, &parsed.path);
                    }
                }

                if let Some(location) = response.location() {
                    current_url = if location.starts_with("http://") || location.starts_with("https://") {
                        location.to_string()
                    } else if location.starts_with('/') {
                        format!("{}://{}:{}{}", parsed.scheme, parsed.host, parsed.port, location)
                    } else {
                        let base_path = if let Some(idx) = parsed.path.rfind('/') {
                            &parsed.path[..idx + 1]
                        } else {
                            "/"
                        };
                        format!("{}://{}:{}{}{}", parsed.scheme, parsed.host, parsed.port, base_path, location)
                    };

                    redirects += 1;
                    continue;
                }
            }

            if self.options.use_cookies {
                let mut jar = super::cookies::get_cookie_jar().lock();
                for set_cookie in response.get_set_cookie_headers() {
                    jar.parse_set_cookie(set_cookie, &parsed.host, &parsed.path);
                }
            }

            let mut final_response = response;
            final_response.final_url = current_url;
            final_response.redirects = redirects;
            return Ok(final_response);
        }
    }

    fn do_request(&self, url: &ParsedUrl, method: HttpMethod, body: Option<&[u8]>) -> Result<HttpResponse, &'static str> {
        let ip = resolve_host(&url.host)?;
        let request = build_request(url, method, body, &self.options);

        let stack = crate::network::stack::get_network_stack()
            .ok_or("network stack not initialized")?;

        let raw_response = stack.http_request(ip, url.port, &request, self.options.timeout_ms as u32)?;
        parse_response(&raw_response)
    }

    fn do_https_request(&self, url: &ParsedUrl, method: HttpMethod, body: Option<&[u8]>) -> Result<HttpResponse, &'static str> {
        let ip = resolve_host(&url.host)?;
        let request = build_request(url, method, body, &self.options);

        let stack = crate::network::stack::get_network_stack()
            .ok_or("network stack not initialized")?;
        let stack_socket = crate::network::stack::TcpSocket::new();
        let conn_id = stack_socket.connection_id();
        stack.tcp_connect(&stack_socket, ip, url.port).map_err(|_| "TCP connect failed")?;
        let socket = crate::network::tcp::TcpSocket::from_connection(conn_id);

        let mut tls = TLSConnection::new();

        let verifier = crate::network::onion::tls::get_cert_verifier()
            .unwrap_or(&crate::network::onion::tls::HTTPS_CERT_VERIFIER);

        let _session_info = tls.handshake_full(
            &socket,
            Some(&url.host),
            Some(&["http/1.1"]),
            verifier,
        ).map_err(|_| "TLS handshake failed")?;

        let encrypted_request = tls.encrypt_app(&request)
            .map_err(|_| "TLS encrypt failed")?;
        let wrapped = wrap_tls_record(0x17, &encrypted_request);
        stack.tcp_send(conn_id, &wrapped).map_err(|_| "TCP send failed")?;

        let mut response_data = Vec::new();
        let deadline_ms = crate::time::timestamp_millis() + self.options.timeout_ms;

        loop {
            if crate::time::timestamp_millis() > deadline_ms {
                return Err("timeout");
            }

            let received = stack.tcp_receive(conn_id, 8192).map_err(|_| "TCP recv failed")?;
            if received.is_empty() {
                break;
            }
            let n = received.len();
            let buffer = &received[..];

            let mut offset = 0;
            while offset + 5 <= n {
                let content_type = buffer[offset];
                let record_len = u16::from_be_bytes([buffer[offset + 3], buffer[offset + 4]]) as usize;

                if offset + 5 + record_len > n {
                    break;
                }

                let record_data = &buffer[offset + 5..offset + 5 + record_len];

                if content_type == 0x17 {
                    match tls.decrypt_app(record_data) {
                        Ok(plaintext) => {
                            if !plaintext.is_empty() {
                                let data = &plaintext[..plaintext.len() - 1];
                                response_data.extend_from_slice(data);
                            }
                        }
                        Err(_) => return Err("TLS decrypt failed"),
                    }
                } else if content_type == 0x15 {
                    break;
                }

                offset += 5 + record_len;
            }

            if response_data.len() > 4 {
                if let Some(header_end) = find_sequence(&response_data, b"\r\n\r\n") {
                    if is_response_complete(&response_data, header_end) || response_data.len() > MAX_RESPONSE_SIZE {
                        break;
                    }
                }
            }
        }

        let _ = stack.tcp_close(conn_id);

        if response_data.is_empty() {
            return Err("empty response");
        }

        parse_response(&response_data)
    }
}

/*
 * check if HTTP response is complete based on Content-Length or chunked encoding.
 * header_end is the index where "\r\n\r\n" starts (body starts at header_end + 4).
 */
fn is_response_complete(data: &[u8], header_end: usize) -> bool {
    let headers = &data[..header_end];
    let body_start = header_end + 4;
    let body = &data[body_start..];

    /* check for Content-Length header */
    if let Some(content_length) = parse_content_length(headers) {
        return body.len() >= content_length;
    }

    /* check for chunked transfer encoding */
    if has_chunked_encoding(headers) {
        /* look for "0\r\n\r\n" or "0\r\n" followed by trailers and "\r\n\r\n" */
        return find_chunked_terminator(body);
    }

    /* no Content-Length and not chunked - can't determine, keep reading */
    false
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let header_str = core::str::from_utf8(headers).ok()?;
    for line in header_str.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let value = line[15..].trim();
            return value.parse().ok();
        }
    }
    None
}

fn has_chunked_encoding(headers: &[u8]) -> bool {
    let header_str = match core::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in header_str.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            return true;
        }
    }
    false
}

fn find_chunked_terminator(body: &[u8]) -> bool {
    /*
     * chunked encoding ends with "0\r\n" (final chunk size) followed by
     * optional trailers and then "\r\n" (or just "\r\n\r\n" if no trailers).
     * simplest terminator pattern is "0\r\n\r\n".
     */
    if body.len() < 5 {
        return false;
    }

    /* search for "0\r\n" followed eventually by "\r\n\r\n" */
    let mut i = 0;
    while i + 5 <= body.len() {
        /* look for "0\r\n" at start of a chunk size line */
        if body[i] == b'0' && body[i + 1] == b'\r' && body[i + 2] == b'\n' {
            /* check if followed immediately by "\r\n" (no trailers) */
            if body[i + 3] == b'\r' && body[i + 4] == b'\n' {
                return true;
            }
            /* could have trailers - look for "\r\n\r\n" after the "0\r\n" */
            if let Some(_) = find_sequence(&body[i + 3..], b"\r\n\r\n") {
                return true;
            }
        }
        /* move to next line */
        if let Some(pos) = find_sequence(&body[i..], b"\r\n") {
            i += pos + 2;
        } else {
            break;
        }
    }
    false
}
