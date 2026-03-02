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

use core::str;
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::{bytes_to_str, parse_usize};

pub fn cmd_head(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: head [-n lines] <file>", COLOR_TEXT_DIM);
        return;
    };

    let (num_lines, path) = parse_head_args(args);

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"head: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::read_file(path_str) {
        Ok(data) => {
            let content = match str::from_utf8(&data) {
                Ok(s) => s,
                Err(_) => {
                    print_line(b"head: file is not valid UTF-8 text", COLOR_RED);
                    return;
                }
            };

            let mut lines_shown = 0;
            for line in content.lines() {
                if lines_shown >= num_lines {
                    break;
                }
                let line_bytes = line.as_bytes();
                let line_len = line_bytes.len().min(80);
                let mut output = [0u8; 80];
                output[..line_len].copy_from_slice(&line_bytes[..line_len]);
                print_line(&output[..line_len], COLOR_TEXT);
                lines_shown += 1;
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..6].copy_from_slice(b"head: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[6..6+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..6+err_len], COLOR_RED);
        }
    }
}

fn parse_head_args(args: &[u8]) -> (usize, &[u8]) {
    if args.starts_with(b"-n ") {
        let rest = trim_bytes(&args[3..]);
        if let Some(space_pos) = rest.iter().position(|&c| c == b' ') {
            let num_str = &rest[..space_pos];
            let path = trim_bytes(&rest[space_pos+1..]);
            let num = parse_usize(num_str).unwrap_or(10);
            return (num, path);
        }
    }
    (10, args)
}
