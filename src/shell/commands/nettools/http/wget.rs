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

use alloc::string::ToString;
use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM};
use crate::shell::commands::utils::{format_num_simple, trim_bytes};
use crate::shell::output::print_line;

pub fn cmd_wget(cmd: &[u8]) {
    let url = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: wget <url> [-O <output>]", COLOR_TEXT_DIM);
        return;
    };

    if url.is_empty() {
        print_line(b"wget: URL required", COLOR_RED);
        return;
    }

    let url_str = match core::str::from_utf8(url) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"wget: invalid URL", COLOR_RED);
            return;
        }
    };

    let (actual_url, output_file) = parse_wget_args(url_str);

    let mut line = [0u8; 80];
    line[..14].copy_from_slice(b"Connecting to ");
    let url_len = actual_url.len().min(50);
    line[14..14 + url_len].copy_from_slice(&actual_url.as_bytes()[..url_len]);
    print_line(&line[..14 + url_len], COLOR_TEXT);

    print_line(b"Routing through Tor...", COLOR_ACCENT);

    match crate::network::http_client::fetch_response(actual_url) {
        Ok(response) => {
            if response.is_success() {
                let body_len = response.body.len();

                let filename = if let Some(f) = output_file {
                    f.to_string()
                } else {
                    extract_filename_from_url(actual_url)
                };

                match crate::fs::ramfs::write_file(&filename, &response.body) {
                    Ok(_) => {
                        print_line(b"", COLOR_TEXT);

                        let mut status_line = [0u8; 80];
                        let msg = format_wget_status(response.status_code, body_len, &filename);
                        let msg_len = msg.len().min(80);
                        status_line[..msg_len].copy_from_slice(&msg.as_bytes()[..msg_len]);
                        print_line(&status_line[..msg_len], COLOR_GREEN);
                    }
                    Err(_) => {
                        print_line(b"wget: failed to write file", COLOR_RED);
                    }
                }
            } else {
                let mut err_line = [0u8; 48];
                err_line[..12].copy_from_slice(b"HTTP Error: ");
                let mut code_buf = [0u8; 16];
                let code_len = format_num_simple(&mut code_buf, response.status_code as usize);
                err_line[12..12 + code_len].copy_from_slice(&code_buf[..code_len]);
                print_line(&err_line[..12 + code_len], COLOR_RED);
            }
        }
        Err(e) => {
            let mut err_line = [0u8; 64];
            err_line[..7].copy_from_slice(b"wget: ");
            let e_bytes = e.as_bytes();
            let e_len = e_bytes.len().min(50);
            err_line[7..7 + e_len].copy_from_slice(&e_bytes[..e_len]);
            print_line(&err_line[..7 + e_len], COLOR_RED);
        }
    }
}

fn parse_wget_args(input: &str) -> (&str, Option<&str>) {
    if let Some(idx) = input.find(" -O ") {
        let url = input[..idx].trim();
        let output = input[idx + 4..].trim();
        if !output.is_empty() {
            return (url, Some(output));
        }
    }
    (input, None)
}

fn extract_filename_from_url(url: &str) -> alloc::string::String {
    use alloc::string::String;

    if let Some(path_start) = url.rfind('/') {
        let path = &url[path_start + 1..];
        let path = if let Some(q) = path.find('?') {
            &path[..q]
        } else {
            path
        };
        if !path.is_empty() && !path.contains('/') {
            return String::from(path);
        }
    }
    String::from("index.html")
}

fn format_wget_status(code: u16, bytes: usize, filename: &str) -> alloc::string::String {
    use alloc::format;
    format!("{} OK - {} bytes saved to '{}'", code, bytes, filename)
}
