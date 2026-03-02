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

use alloc::vec::Vec;
use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_YELLOW};
use crate::shell::commands::utils::trim_bytes;
use crate::shell::output::print_line;

pub fn cmd_curl(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: curl [-I] [-v] <url>", COLOR_TEXT_DIM);
        return;
    };

    if args.is_empty() {
        print_line(b"curl: URL required", COLOR_RED);
        return;
    }

    let args_str = match core::str::from_utf8(args) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"curl: invalid URL", COLOR_RED);
            return;
        }
    };

    let (url, head_only, verbose) = parse_curl_args(args_str);

    if url.is_empty() {
        print_line(b"curl: URL required", COLOR_RED);
        return;
    }

    if verbose {
        let mut line = [0u8; 80];
        line[..14].copy_from_slice(b"> Connecting: ");
        let url_len = url.len().min(50);
        line[14..14 + url_len].copy_from_slice(&url.as_bytes()[..url_len]);
        print_line(&line[..14 + url_len], COLOR_TEXT_DIM);
        print_line(b"> Routing through Tor...", COLOR_TEXT_DIM);
    }

    let mut options = crate::network::http_client::HttpRequestOptions::default();
    options.verbose = verbose;

    let method = if head_only {
        crate::network::http_client::HttpMethod::Head
    } else {
        crate::network::http_client::HttpMethod::Get
    };

    let client = crate::network::http_client::HttpClient::with_options(options);

    match client.request(url, method, None) {
        Ok(response) => {
            if verbose || head_only {
                let mut status_line = [0u8; 64];
                let status = alloc::format!(
                    "HTTP/1.1 {} {}",
                    response.status_code,
                    response.status_text
                );
                let status_len = status.len().min(64);
                status_line[..status_len].copy_from_slice(&status.as_bytes()[..status_len]);
                print_line(&status_line[..status_len], COLOR_GREEN);

                for (name, value) in &response.headers {
                    let header = alloc::format!("{}: {}", name, value);
                    let mut header_line = [0u8; 80];
                    let header_len = header.len().min(80);
                    header_line[..header_len].copy_from_slice(&header.as_bytes()[..header_len]);
                    print_line(&header_line[..header_len], COLOR_TEXT_DIM);
                }
                print_line(b"", COLOR_TEXT);
            }

            if !head_only {
                print_response_body(&response);
            }
        }
        Err(e) => {
            let mut err_line = [0u8; 64];
            err_line[..7].copy_from_slice(b"curl: ");
            let e_bytes = e.as_bytes();
            let e_len = e_bytes.len().min(50);
            err_line[7..7 + e_len].copy_from_slice(&e_bytes[..e_len]);
            print_line(&err_line[..7 + e_len], COLOR_RED);
        }
    }
}

fn print_response_body(response: &crate::network::http_client::HttpResponse) {
    if let Some(text) = response.body_text() {
        for line in text.lines() {
            let line_bytes = line.as_bytes();
            let mut offset = 0;
            while offset < line_bytes.len() {
                let chunk_len = (line_bytes.len() - offset).min(120);
                let mut out = [0u8; 120];
                out[..chunk_len].copy_from_slice(&line_bytes[offset..offset + chunk_len]);
                print_line(&out[..chunk_len], COLOR_TEXT);
                offset += chunk_len;
            }
            if line_bytes.is_empty() {
                print_line(b"", COLOR_TEXT);
            }
        }
    } else {
        let msg = alloc::format!("[Binary data: {} bytes]", response.body.len());
        let mut line = [0u8; 48];
        let msg_len = msg.len().min(48);
        line[..msg_len].copy_from_slice(&msg.as_bytes()[..msg_len]);
        print_line(&line[..msg_len], COLOR_YELLOW);
    }
}

fn parse_curl_args(input: &str) -> (&str, bool, bool) {
    let mut head_only = false;
    let mut verbose = false;
    let mut url = input;

    let parts: Vec<&str> = input.split_whitespace().collect();
    let mut url_idx = 0;

    for (i, part) in parts.iter().enumerate() {
        if *part == "-I" || *part == "--head" {
            head_only = true;
            url_idx = i + 1;
        } else if *part == "-v" || *part == "--verbose" {
            verbose = true;
            url_idx = i + 1;
        } else if !part.starts_with('-') {
            url = part;
            break;
        }
    }

    if url_idx < parts.len() {
        url = parts[url_idx];
    }

    (url, head_only, verbose)
}
