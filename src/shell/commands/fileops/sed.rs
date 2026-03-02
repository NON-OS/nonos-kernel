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
use core::str;
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_sed(cmd: &[u8]) {
    let args = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        print_line(b"Usage: sed 's/pattern/replacement/' <file>", COLOR_TEXT_DIM);
        return;
    };

    let (pattern, replacement, global, path) = match parse_sed_args(args) {
        Some(x) => x,
        None => {
            print_line(b"sed: invalid expression", COLOR_RED);
            return;
        }
    };

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"sed: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::read_file(path_str) {
        Ok(data) => {
            let content = match str::from_utf8(&data) {
                Ok(s) => s,
                Err(_) => {
                    print_line(b"sed: file is not valid UTF-8 text", COLOR_RED);
                    return;
                }
            };

            for line in content.lines() {
                let result: String = if global {
                    line.replace(pattern, replacement)
                } else {
                    line.replacen(pattern, replacement, 1)
                };

                let result_bytes = result.as_bytes();
                let len = result_bytes.len().min(80);
                let mut output = [0u8; 80];
                output[..len].copy_from_slice(&result_bytes[..len]);
                print_line(&output[..len], COLOR_TEXT);
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..5].copy_from_slice(b"sed: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[5..5+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..5+err_len], COLOR_RED);
        }
    }
}

fn parse_sed_args(args: &[u8]) -> Option<(&str, &str, bool, &[u8])> {
    if !args.starts_with(b"'s/") && !args.starts_with(b"s/") {
        return None;
    }

    let start = if args[0] == b'\'' { 3 } else { 2 };
    let rest = &args[start..];

    let mut pattern_end = 0;
    let mut escaped = false;
    for (i, &c) in rest.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if c == b'/' {
            pattern_end = i;
            break;
        }
    }

    if pattern_end == 0 {
        return None;
    }

    let pattern = bytes_to_str(&rest[..pattern_end])?;
    let after_pattern = &rest[pattern_end + 1..];

    let mut replacement_end = 0;
    let mut escaped = false;
    for (i, &c) in after_pattern.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
        } else if c == b'/' {
            replacement_end = i;
            break;
        }
    }

    let replacement = bytes_to_str(&after_pattern[..replacement_end])?;
    let after_replacement = &after_pattern[replacement_end + 1..];

    let global = after_replacement.starts_with(b"g") ||
                 after_replacement.starts_with(b"g'") ||
                 after_replacement.starts_with(b"g ");

    let path_start = if after_replacement.starts_with(b"g' ") {
        3
    } else if after_replacement.starts_with(b"g ") {
        2
    } else if after_replacement.starts_with(b"' ") {
        2
    } else if after_replacement.starts_with(b" ") {
        1
    } else {
        0
    };

    let path = trim_bytes(&after_replacement[path_start..]);

    Some((pattern, replacement, global, path))
}
