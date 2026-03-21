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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use crate::graphics::window::ecosystem::state as window_state;
use super::super::engine;
use super::super::history::add_history;
use super::super::tabs::active_tab;
use super::state::*;

pub(super) fn process_response() {
    let response_data = RESPONSE_DATA.lock().clone();
    crate::sys::serial::print(b"[NAV] process_response len=");
    crate::sys::serial::print_dec(response_data.len() as u64);
    crate::sys::serial::println(b"");
    let url = PENDING_URL.lock().clone().unwrap_or_default();

    // Check for HTTP redirect (301/302/303/307/308)
    if let Some(redirect_url) = extract_redirect(&response_data, &url) {
        let count = REDIRECT_COUNT.load(Ordering::Relaxed);
        if count < MAX_REDIRECTS {
            crate::sys::serial::print(b"[NAV] redirect -> ");
            crate::sys::serial::println(redirect_url.as_bytes());
            REDIRECT_COUNT.fetch_add(1, Ordering::Relaxed);
            cleanup_navigation();
            set_state(NavState::Done);
            // Re-navigate to the redirect target
            super::api::navigate_internal(&redirect_url);
            return;
        }
        crate::sys::serial::println(b"[NAV] too many redirects");
    }

    REDIRECT_COUNT.store(0, Ordering::Relaxed);

    let body = extract_body(&response_data);
    crate::sys::serial::print(b"[NAV] body len=");
    crate::sys::serial::print_dec(body.len() as u64);
    crate::sys::serial::println(b"");

    window_state::set_base_url(&url);
    window_state::clear_page_links();

    if let Some(tab) = active_tab() {
        let mut tab = tab;
        tab.url = url.clone();
        tab.content = body.clone();
        let title = extract_title(&body).unwrap_or_else(|| String::from("Untitled"));
        tab.title = title.clone();
        add_history(&url, &title);
    }

    let content_str = core::str::from_utf8(&body).unwrap_or("");
    let (lines, links) = engine::render_to_lines_with_links(content_str);

    // Also produce the rich RenderOutput for the graphics layer
    let render_output = engine::render_page(content_str, 800);

    crate::sys::serial::print(b"[NAV] rendered lines=");
    crate::sys::serial::print_dec(lines.len() as u64);
    crate::sys::serial::print(b", links=");
    crate::sys::serial::print_dec(links.len() as u64);
    crate::sys::serial::println(b"");

    for (line_idx, start_x, end_x, href) in links {
        window_state::add_page_link(line_idx, start_x, end_x, &href);
    }

    let title = extract_title(&body).unwrap_or_else(|| String::from("Untitled"));
    window_state::set_page_title(&title);

    {
        let mut page_content = window_state::PAGE_CONTENT.lock();
        page_content.clear();
        window_state::PAGE_TOTAL_LINES.store(render_output.lines.len(), Ordering::Relaxed);
        page_content.extend(lines);
    }
    {
        *window_state::PAGE_RENDER.lock() = Some(render_output);
    }
    window_state::PAGE_SCROLL.store(0, Ordering::Relaxed);
    window_state::LOADING.store(false, Ordering::Relaxed);
    window_state::mark_content_changed();

    cleanup_navigation();
    set_state(NavState::Done);
}

/// Check if the HTTP response is a redirect (301/302/303/307/308) and extract
/// the `Location` header, resolving relative URLs against `base_url`.
fn extract_redirect(data: &[u8], base_url: &str) -> Option<String> {
    let header_end = find_header_end(data)?;
    let headers = core::str::from_utf8(&data[..header_end]).ok()?;

    // Check status line for redirect codes
    let status_line = headers.lines().next()?;
    let is_redirect = status_line.contains(" 301 ")
        || status_line.contains(" 302 ")
        || status_line.contains(" 303 ")
        || status_line.contains(" 307 ")
        || status_line.contains(" 308 ");
    if !is_redirect {
        return None;
    }

    // Extract Location header
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("location:") {
            let location = line[9..].trim();
            if location.starts_with("http://") || location.starts_with("https://") {
                return Some(String::from(location));
            }
            // Relative URL — resolve against base
            return Some(resolve_relative_url(base_url, location));
        }
    }
    None
}

/// Resolve a relative URL path against a base URL.
fn resolve_relative_url(base: &str, relative: &str) -> String {
    // Absolute path: keep scheme + host from base
    if relative.starts_with('/') {
        let scheme_end = base.find("://").map(|i| i + 3).unwrap_or(0);
        let host_end = base[scheme_end..].find('/').map(|i| i + scheme_end).unwrap_or(base.len());
        let mut result = String::from(&base[..host_end]);
        result.push_str(relative);
        return result;
    }
    // Fallback: treat as absolute
    String::from(relative)
}

pub(super) fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

pub(super) fn is_response_complete(data: &[u8]) -> bool {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let body_start = header_end + 4;
        let body_len = data.len() - body_start;

        // Content-Length path
        if let Some(cl) = parse_content_length(headers) {
            return body_len >= cl;
        }

        // Chunked transfer-encoding: the stream ends with "0\r\n\r\n"
        if is_chunked_transfer(headers) {
            return data.len() >= 5
                && data[data.len() - 5..] == *b"0\r\n\r\n";
        }
    }
    false
}

const MAX_CONTENT_LENGTH: usize = 16 * 1024 * 1024;

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let val = line[15..].trim();
            let len: usize = val.parse().ok()?;
            if len > MAX_CONTENT_LENGTH {
                return None;
            }
            return Some(len);
        }
    }
    None
}

fn extract_body(data: &[u8]) -> Vec<u8> {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let raw_body = &data[header_end + 4..];

        if is_chunked_transfer(headers) {
            return decode_chunked(raw_body);
        }

        Vec::from(raw_body)
    } else {
        Vec::from(data)
    }
}

/// Returns `true` when the headers contain `Transfer-Encoding: chunked`.
fn is_chunked_transfer(headers: &[u8]) -> bool {
    let s = match core::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") {
            return lower[18..].trim().contains("chunked");
        }
    }
    false
}

/// Decodes an HTTP chunked body into a flat byte vector.
///
/// Format per RFC 7230 §4.1:
///   <hex-size>\r\n<chunk-data>\r\n … 0\r\n\r\n
///
/// Returns whatever was successfully decoded if the stream is truncated.
fn decode_chunked(mut data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        // Find the chunk-size line ending with \r\n
        let crlf = match data.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => pos,
            None => break,
        };

        // Parse the hex chunk size (ignore optional chunk-extensions after ';')
        let size_str = match core::str::from_utf8(&data[..crlf]) {
            Ok(s) => s.split(';').next().unwrap_or("").trim(),
            Err(_) => break,
        };
        let chunk_len = match usize::from_str_radix(size_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };

        // A zero-length chunk signals the end of the body.
        if chunk_len == 0 {
            break;
        }

        let chunk_start = crlf + 2;
        let chunk_end = chunk_start + chunk_len;

        // Guard against truncated streams
        if chunk_end > data.len() {
            // Partial chunk — take what's available
            output.extend_from_slice(&data[chunk_start..]);
            break;
        }

        output.extend_from_slice(&data[chunk_start..chunk_end]);

        // Skip the trailing \r\n after the chunk data
        let next = chunk_end + 2;
        if next > data.len() {
            break;
        }
        data = &data[next..];
    }
    output
}

fn extract_title(body: &[u8]) -> Option<String> {
    let html = core::str::from_utf8(body).ok()?;
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start..].find("</title>")?;
    let title = &html[start + 7..start + end];
    Some(String::from(title.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── find_header_end ─────────────────────────────────────────────────

    #[test]
    fn test_find_header_end_basic() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(find_header_end(data), Some(34));
    }

    #[test]
    fn test_find_header_end_no_body() {
        let data = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(find_header_end(data), Some(15));
    }

    #[test]
    fn test_find_header_end_missing() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert_eq!(find_header_end(data), None);
    }

    // ── is_chunked_transfer ─────────────────────────────────────────────

    #[test]
    fn test_is_chunked_transfer_true() {
        let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n";
        assert!(is_chunked_transfer(headers));
    }

    #[test]
    fn test_is_chunked_transfer_false() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n";
        assert!(!is_chunked_transfer(headers));
    }

    #[test]
    fn test_is_chunked_transfer_case_insensitive() {
        let headers = b"transfer-ENCODING: Chunked\r\n";
        assert!(is_chunked_transfer(headers));
    }

    // ── decode_chunked ──────────────────────────────────────────────────

    #[test]
    fn test_decode_chunked_basic() {
        // "5\r\nhello\r\n0\r\n\r\n"
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(input), b"hello");
    }

    #[test]
    fn test_decode_chunked_multiple() {
        // Two chunks: "hello" and " world"
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(input), b"hello world");
    }

    #[test]
    fn test_decode_chunked_with_extension() {
        // Chunk extension should be ignored (RFC 7230 §4.1.1)
        let input = b"5;ext=val\r\nhello\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(input), b"hello");
    }

    #[test]
    fn test_decode_chunked_truncated() {
        // Incomplete — takes what's available
        let input = b"a\r\nhello";
        let result = decode_chunked(input);
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_decode_chunked_empty_body() {
        let input = b"0\r\n\r\n";
        assert_eq!(decode_chunked(input), b"");
    }

    // ── is_response_complete ────────────────────────────────────────────

    #[test]
    fn test_is_response_complete_content_length() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(is_response_complete(data));
    }

    #[test]
    fn test_is_response_complete_content_length_partial() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
        assert!(!is_response_complete(data));
    }

    #[test]
    fn test_is_response_complete_chunked() {
        let mut data = Vec::new();
        data.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        data.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        assert!(is_response_complete(&data));
    }

    #[test]
    fn test_is_response_complete_chunked_partial() {
        let mut data = Vec::new();
        data.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        data.extend_from_slice(b"5\r\nhello\r\n");
        assert!(!is_response_complete(&data));
    }

    // ── extract_body ────────────────────────────────────────────────────

    #[test]
    fn test_extract_body_plain() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(extract_body(data), b"hello");
    }

    #[test]
    fn test_extract_body_chunked() {
        let mut data = Vec::new();
        data.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        data.extend_from_slice(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        assert_eq!(extract_body(&data), b"hello world");
    }

    // ── extract_title ───────────────────────────────────────────────────

    #[test]
    fn test_extract_title_basic() {
        let body = b"<html><head><title>My Page</title></head></html>";
        assert_eq!(extract_title(body), Some(String::from("My Page")));
    }

    #[test]
    fn test_extract_title_missing() {
        let body = b"<html><body>no title here</body></html>";
        assert_eq!(extract_title(body), None);
    }

    /// Simulate example.com-style chunked response to verify full pipeline
    #[test]
    fn test_extract_body_example_com_chunked() {
        let html = "<!doctype html><html><head><title>Example Domain</title></head>\
                     <body><h1>Example Domain</h1><p>This domain is for use in \
                     illustrative examples.</p></body></html>";
        let chunk_hex = format!("{:x}", html.len());
        let mut data = Vec::new();
        data.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n");
        data.extend_from_slice(chunk_hex.as_bytes());
        data.extend_from_slice(b"\r\n");
        data.extend_from_slice(html.as_bytes());
        data.extend_from_slice(b"\r\n0\r\n\r\n");

        assert!(is_response_complete(&data));
        let body = extract_body(&data);
        assert_eq!(body.len(), html.len());
        assert_eq!(core::str::from_utf8(&body).unwrap(), html);
    }
}
