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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_YELLOW, COLOR_RED};
use crate::fs::ramfs;
use crate::shell::commands::utils::{trim_bytes, format_num_simple};
use crate::shell::commands::pipeline;

use super::cwd::get_cwd;

pub fn cmd_echo(cmd: &[u8]) {
    if cmd.len() > 5 {
        let text = trim_bytes(&cmd[5..]);
        if text.is_empty() {
            print_line(b"", COLOR_TEXT);
        } else {
            print_line(text, COLOR_TEXT);
        }
    } else {
        print_line(b"", COLOR_TEXT);
    }
}

pub fn cmd_cat(cmd: &[u8]) {
    let path = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        b"" as &[u8]
    };

    let data: alloc::vec::Vec<u8>;

    if path.is_empty() {
        if pipeline::has_stdin() {
            data = pipeline::take_stdin().unwrap_or_default();
        } else {
            print_line(b"Usage: cat <filename>", COLOR_TEXT_DIM);
            return;
        }
    } else {
        let path_str = match str::from_utf8(path) {
            Ok(s) => s,
            Err(_) => {
                print_line(b"cat: invalid path encoding", COLOR_RED);
                return;
            }
        };

        let full_path = if path_str.starts_with('/') {
            String::from(path_str)
        } else {
            let cwd = get_cwd();
            if cwd.ends_with('/') {
                alloc::format!("{}{}", cwd, path_str)
            } else {
                alloc::format!("{}/{}", cwd, path_str)
            }
        };

        data = match ramfs::read_file(&full_path) {
            Ok(d) => d,
            Err(e) => {
                let mut line = [0u8; 80];
                line[..5].copy_from_slice(b"cat: ");
                let err_str = e.as_str().as_bytes();
                let err_len = err_str.len().min(60);
                line[5..5+err_len].copy_from_slice(&err_str[..err_len]);
                print_line(&line[..5+err_len], COLOR_RED);
                return;
            }
        };
    }

    match str::from_utf8(&data) {
        Ok(content) => {
            for line in content.lines() {
                let line_bytes = line.as_bytes();
                let line_len = line_bytes.len().min(80);
                let mut output = [0u8; 80];
                output[..line_len].copy_from_slice(&line_bytes[..line_len]);
                print_line(&output[..line_len], COLOR_TEXT);
            }
        }
        Err(_) => {
            print_line(b"cat: file is binary data", COLOR_YELLOW);
            let mut line = [0u8; 32];
            line[..7].copy_from_slice(b"Size: ");
            let size_len = format_num_simple(&mut line[7..], data.len());
            line[7+size_len..7+size_len+6].copy_from_slice(b" bytes");
            print_line(&line[..13+size_len], COLOR_TEXT_DIM);
        }
    }
}
