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
use crate::shell::commands::utils::{trim_bytes, format_num_simple};
use crate::shell::commands::pipeline;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_uniq(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        b"" as &[u8]
    };

    let (count_mode, path) = if args.starts_with(b"-c ") {
        (true, trim_bytes(&args[3..]))
    } else if args == b"-c" {
        (true, b"" as &[u8])
    } else {
        (false, args)
    };

    let data: Vec<u8>;
    if path.is_empty() {
        if pipeline::has_stdin() {
            data = pipeline::take_stdin().unwrap_or_default();
        } else {
            print_line(b"Usage: uniq [-c] [file]", COLOR_TEXT_DIM);
            return;
        }
    } else {
        let path_str = match bytes_to_str(path) {
            Some(s) => s,
            None => {
                print_line(b"uniq: invalid path encoding", COLOR_RED);
                return;
            }
        };

        data = match ramfs::read_file(path_str) {
            Ok(d) => d,
            Err(e) => {
                let mut line = [0u8; 80];
                line[..6].copy_from_slice(b"uniq: ");
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
            print_line(b"uniq: input is not valid UTF-8 text", COLOR_RED);
            return;
        }
    };

    let mut prev_line: Option<&str> = None;
    let mut count = 0usize;

    for line in content.lines() {
        if Some(line) == prev_line {
            count += 1;
        } else {
            if let Some(prev) = prev_line {
                output_uniq_line(prev, count, count_mode);
            }
            prev_line = Some(line);
            count = 1;
        }
    }

    if let Some(prev) = prev_line {
        output_uniq_line(prev, count, count_mode);
    }
}

fn output_uniq_line(line: &str, count: usize, count_mode: bool) {
    let line_bytes = line.as_bytes();
    let mut output = [0u8; 80];

    if count_mode {
        let count_len = format_num_simple(&mut output, count);
        output[count_len] = b' ';
        let line_len = line_bytes.len().min(70 - count_len);
        output[count_len+1..count_len+1+line_len].copy_from_slice(&line_bytes[..line_len]);
        print_line(&output[..count_len+1+line_len], COLOR_TEXT);
    } else {
        let line_len = line_bytes.len().min(80);
        output[..line_len].copy_from_slice(&line_bytes[..line_len]);
        print_line(&output[..line_len], COLOR_TEXT);
    }
}
