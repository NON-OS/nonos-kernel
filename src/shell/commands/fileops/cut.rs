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
use core::str;
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::shell::commands::pipeline;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_cut(cmd: &[u8]) {
    let args = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        b"" as &[u8]
    };

    let (delimiter, field, path) = parse_cut_args(args);

    let data: Vec<u8>;
    if path.is_empty() {
        if pipeline::has_stdin() {
            data = pipeline::take_stdin().unwrap_or_default();
        } else {
            print_line(b"Usage: cut -d<delim> -f<field> [file]", COLOR_TEXT_DIM);
            print_line(b"Example: cut -d: -f1 /etc/passwd", COLOR_TEXT_DIM);
            return;
        }
    } else {
        let path_str = match bytes_to_str(path) {
            Some(s) => s,
            None => {
                print_line(b"cut: invalid path encoding", COLOR_RED);
                return;
            }
        };

        data = match ramfs::read_file(path_str) {
            Ok(d) => d,
            Err(e) => {
                let mut line = [0u8; 80];
                line[..5].copy_from_slice(b"cut: ");
                let err_str = e.as_str().as_bytes();
                let err_len = err_str.len().min(60);
                line[5..5+err_len].copy_from_slice(&err_str[..err_len]);
                print_line(&line[..5+err_len], COLOR_RED);
                return;
            }
        };
    }

    let content = match str::from_utf8(&data) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"cut: input is not valid UTF-8 text", COLOR_RED);
            return;
        }
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split(delimiter as char).collect();
        if field > 0 && field <= parts.len() {
            let part = parts[field - 1];
            let part_bytes = part.as_bytes();
            let len = part_bytes.len().min(80);
            let mut output = [0u8; 80];
            output[..len].copy_from_slice(&part_bytes[..len]);
            print_line(&output[..len], COLOR_TEXT);
        }
    }
}

fn parse_cut_args(args: &[u8]) -> (u8, usize, &[u8]) {
    let mut delimiter = b'\t';
    let mut field = 1usize;
    let mut rest = args;

    while !rest.is_empty() {
        if rest.starts_with(b"-d") && rest.len() > 2 {
            delimiter = rest[2];
            rest = trim_bytes(&rest[3..]);
        } else if rest.starts_with(b"-f") && rest.len() > 2 {
            let mut i = 2;
            while i < rest.len() && rest[i] >= b'0' && rest[i] <= b'9' {
                field = field * 10 + (rest[i] - b'0') as usize;
                i += 1;
            }
            rest = trim_bytes(&rest[i..]);
        } else {
            break;
        }
    }

    (delimiter, field, rest)
}
