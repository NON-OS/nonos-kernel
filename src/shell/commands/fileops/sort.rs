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

pub fn cmd_sort(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        b"" as &[u8]
    };

    let (reverse, numeric, path) = parse_sort_flags(args);

    let data: Vec<u8>;
    if path.is_empty() {
        if pipeline::has_stdin() {
            data = pipeline::take_stdin().unwrap_or_default();
        } else {
            print_line(b"Usage: sort [-r] [-n] [file]", COLOR_TEXT_DIM);
            return;
        }
    } else {
        let path_str = match bytes_to_str(path) {
            Some(s) => s,
            None => {
                print_line(b"sort: invalid path encoding", COLOR_RED);
                return;
            }
        };

        data = match ramfs::read_file(path_str) {
            Ok(d) => d,
            Err(e) => {
                let mut line = [0u8; 80];
                line[..6].copy_from_slice(b"sort: ");
                let err_str = e.as_str().as_bytes();
                let err_len = err_str.len().min(60);
                line[6..6+err_len].copy_from_slice(&err_str[..err_len]);
                print_line(&line[..6+err_len], COLOR_RED);
                return;
            }
        };
    }

    let content = match str::from_utf8(&data) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"sort: input is not valid UTF-8 text", COLOR_RED);
            return;
        }
    };

    let mut lines: Vec<&str> = content.lines().collect();

    if numeric {
        lines.sort_by(|a, b| {
            let na: i64 = a.trim().parse().unwrap_or(0);
            let nb: i64 = b.trim().parse().unwrap_or(0);
            na.cmp(&nb)
        });
    } else {
        lines.sort();
    }

    if reverse {
        lines.reverse();
    }

    for line in lines {
        let line_bytes = line.as_bytes();
        let line_len = line_bytes.len().min(80);
        let mut output = [0u8; 80];
        output[..line_len].copy_from_slice(&line_bytes[..line_len]);
        print_line(&output[..line_len], COLOR_TEXT);
    }
}

fn parse_sort_flags(args: &[u8]) -> (bool, bool, &[u8]) {
    let mut reverse = false;
    let mut numeric = false;
    let mut rest = args;

    loop {
        if rest.starts_with(b"-r ") {
            reverse = true;
            rest = trim_bytes(&rest[3..]);
        } else if rest.starts_with(b"-n ") {
            numeric = true;
            rest = trim_bytes(&rest[3..]);
        } else if rest.starts_with(b"-rn ") || rest.starts_with(b"-nr ") {
            reverse = true;
            numeric = true;
            rest = trim_bytes(&rest[4..]);
        } else {
            break;
        }
    }

    (reverse, numeric, rest)
}
