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
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::{bytes_to_str, split_args};

pub fn cmd_tr(cmd: &[u8]) {
    let args = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        print_line(b"Usage: tr <set1> <set2> <file>", COLOR_TEXT_DIM);
        print_line(b"Example: tr a-z A-Z file.txt", COLOR_TEXT_DIM);
        return;
    };

    let parts = split_args(args);
    if parts.len() < 3 {
        print_line(b"tr: requires set1 set2 file", COLOR_RED);
        return;
    }

    let set1 = parts[0];
    let set2 = parts[1];
    let path_str = match bytes_to_str(parts[2]) {
        Some(s) => s,
        None => {
            print_line(b"tr: invalid path encoding", COLOR_RED);
            return;
        }
    };

    let set1_expanded = expand_set(set1);
    let set2_expanded = expand_set(set2);

    match ramfs::read_file(path_str) {
        Ok(data) => {
            let mut result = Vec::with_capacity(data.len());

            for &c in &data {
                if let Some(pos) = set1_expanded.iter().position(|&x| x == c) {
                    if pos < set2_expanded.len() {
                        result.push(set2_expanded[pos]);
                    } else if let Some(&last_char) = set2_expanded.last() {
                        result.push(last_char);
                    } else {
                        result.push(c);
                    }
                } else {
                    result.push(c);
                }
            }

            for chunk in result.chunks(80) {
                print_line(chunk, COLOR_TEXT);
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..4].copy_from_slice(b"tr: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[4..4+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..4+err_len], COLOR_RED);
        }
    }
}

fn expand_set(set: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < set.len() {
        if i + 2 < set.len() && set[i + 1] == b'-' {
            let start = set[i];
            let end = set[i + 2];
            if start <= end {
                for c in start..=end {
                    result.push(c);
                }
            }
            i += 3;
        } else {
            result.push(set[i]);
            i += 1;
        }
    }

    result
}
