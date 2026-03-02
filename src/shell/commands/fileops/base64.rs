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
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn cmd_base64(cmd: &[u8]) {
    let args = if cmd.len() > 7 {
        trim_bytes(&cmd[7..])
    } else {
        print_line(b"Usage: base64 [-d] <file>", COLOR_TEXT_DIM);
        print_line(b"  -d    Decode (default is encode)", COLOR_TEXT_DIM);
        return;
    };

    let (decode, path) = if args.starts_with(b"-d ") {
        (true, trim_bytes(&args[3..]))
    } else {
        (false, args)
    };

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"base64: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::read_file(path_str) {
        Ok(data) => {
            if decode {
                match base64_decode(&data) {
                    Ok(decoded) => {
                        for chunk in decoded.chunks(80) {
                            print_line(chunk, COLOR_TEXT);
                        }
                    }
                    Err(_) => {
                        print_line(b"base64: invalid base64 input", COLOR_RED);
                    }
                }
            } else {
                let encoded = base64_encode(&data);
                for chunk in encoded.as_bytes().chunks(76) {
                    print_line(chunk, COLOR_TEXT);
                }
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..8].copy_from_slice(b"base64: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[8..8+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..8+err_len], COLOR_RED);
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        result.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
        result.push(BASE64_CHARS[((b0 & 0x03) << 4 | (b1 >> 4)) as usize] as char);

        if i + 1 < data.len() {
            result.push(BASE64_CHARS[((b1 & 0x0f) << 2 | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(BASE64_CHARS[(b2 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

fn base64_decode(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut result = Vec::new();
    let mut buf = [0u8; 4];
    let mut buf_len = 0;

    for &c in data {
        if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
            continue;
        }

        let val = if c >= b'A' && c <= b'Z' {
            c - b'A'
        } else if c >= b'a' && c <= b'z' {
            c - b'a' + 26
        } else if c >= b'0' && c <= b'9' {
            c - b'0' + 52
        } else if c == b'+' {
            62
        } else if c == b'/' {
            63
        } else if c == b'=' {
            64
        } else {
            return Err(());
        };

        buf[buf_len] = val;
        buf_len += 1;

        if buf_len == 4 {
            result.push((buf[0] << 2) | (buf[1] >> 4));
            if buf[2] != 64 {
                result.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if buf[3] != 64 {
                result.push((buf[2] << 6) | buf[3]);
            }
            buf_len = 0;
        }
    }

    Ok(result)
}
