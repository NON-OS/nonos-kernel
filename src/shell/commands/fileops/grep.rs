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
use super::utils::{bytes_to_str, split_args, find_subsequence};

pub fn cmd_grep(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: grep <pattern> [file]", COLOR_TEXT_DIM);
        return;
    };

    let parts = split_args(args);
    if parts.is_empty() {
        print_line(b"grep: pattern required", COLOR_RED);
        return;
    }

    let pattern = parts[0];

    let content_vec: Vec<u8>;
    let content: &str;

    if parts.len() >= 2 {
        let path_str = match bytes_to_str(parts[1]) {
            Some(s) => s,
            None => {
                print_line(b"grep: invalid path encoding", COLOR_RED);
                return;
            }
        };

        content_vec = match ramfs::read_file(path_str) {
            Ok(data) => data,
            Err(e) => {
                let mut line = [0u8; 80];
                line[..6].copy_from_slice(b"grep: ");
                let err_str = e.as_str().as_bytes();
                let err_len = err_str.len().min(60);
                line[6..6+err_len].copy_from_slice(&err_str[..err_len]);
                print_line(&line[..6+err_len], COLOR_RED);
                return;
            }
        };
    } else if pipeline::has_stdin() {
        content_vec = pipeline::take_stdin().unwrap_or_default();
    } else {
        print_line(b"grep: no input (use file or pipe)", COLOR_RED);
        return;
    }

    content = match str::from_utf8(&content_vec) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"grep: input is not valid UTF-8 text", COLOR_RED);
            return;
        }
    };

    let mut matches = 0;
    for (line_num, line) in content.lines().enumerate() {
        let line_bytes = line.as_bytes();
        if find_subsequence(line_bytes, pattern).is_some() {
            let mut output = [0u8; 80];
            let num_len = format_num_simple(&mut output, line_num + 1);
            output[num_len] = b':';
            let line_len = line_bytes.len().min(70 - num_len);
            output[num_len+1..num_len+1+line_len].copy_from_slice(&line_bytes[..line_len]);
            print_line(&output[..num_len+1+line_len], COLOR_TEXT);
            matches += 1;
        }
    }

    if matches == 0 {
        print_line(b"(no matches)", COLOR_TEXT_DIM);
    }
}
