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

use crate::shell::output::print_line;
use crate::shell::commands::utils::{trim_bytes, format_num_simple};
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_wc(cmd: &[u8]) {
    let path = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        print_line(b"Usage: wc <file>", COLOR_TEXT_DIM);
        print_line(b"Counts lines, words, bytes", COLOR_TEXT_DIM);
        return;
    };

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"wc: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::read_file(path_str) {
        Ok(data) => {
            let bytes = data.len();
            let lines = data.iter().filter(|&&c| c == b'\n').count();
            let words = count_words(&data);

            let mut output = [0u8; 64];
            let mut pos = 0;

            pos = write_right_aligned_usize(&mut output, pos, lines, 8);
            pos = write_right_aligned_usize(&mut output, pos, words, 8);
            pos = write_right_aligned_usize(&mut output, pos, bytes, 8);
            output[pos] = b' ';
            pos += 1;

            let path_len = path.len().min(30);
            output[pos..pos+path_len].copy_from_slice(&path[..path_len]);
            pos += path_len;

            print_line(&output[..pos], COLOR_TEXT);
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..4].copy_from_slice(b"wc: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[4..4+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..4+err_len], COLOR_RED);
        }
    }
}

fn count_words(data: &[u8]) -> usize {
    let mut words = 0;
    let mut in_word = false;

    for &c in data {
        let is_ws = c == b' ' || c == b'\t' || c == b'\n' || c == b'\r';
        if is_ws {
            if in_word {
                words += 1;
                in_word = false;
            }
        } else {
            in_word = true;
        }
    }

    if in_word {
        words += 1;
    }

    words
}

fn write_right_aligned_usize(buf: &mut [u8], start: usize, val: usize, width: usize) -> usize {
    let mut num_buf = [0u8; 16];
    let len = format_num_simple(&mut num_buf, val);

    let padding = if width > len { width - len } else { 1 };
    for i in 0..padding {
        buf[start + i] = b' ';
    }

    buf[start + padding..start + padding + len].copy_from_slice(&num_buf[..len]);
    start + padding + len
}
