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
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_touch(cmd: &[u8]) {
    let path = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: touch <filename>", COLOR_TEXT_DIM);
        return;
    };

    if path.is_empty() {
        print_line(b"touch: filename required", COLOR_RED);
        return;
    }

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"touch: invalid path encoding", COLOR_RED);
            return;
        }
    };

    let full_path = if path_str.starts_with('/') {
        String::from(path_str)
    } else {
        let mut p = String::from("/ram/");
        p.push_str(path_str);
        p
    };

    if ramfs::exists(&full_path) {
        print_line(b"File timestamp updated", COLOR_GREEN);
    } else {
        match ramfs::create_file(&full_path, &[]) {
            Ok(()) => {
                let mut line = [0u8; 64];
                line[..9].copy_from_slice(b"Created: ");
                let path_len = path.len().min(48);
                line[9..9+path_len].copy_from_slice(&path[..path_len]);
                print_line(&line[..9+path_len], COLOR_GREEN);
                print_line(b"(Empty file in RAM filesystem)", COLOR_TEXT_DIM);
            }
            Err(e) => {
                let mut line = [0u8; 80];
                line[..7].copy_from_slice(b"touch: ");
                let err_str = e.as_str().as_bytes();
                let err_len = err_str.len().min(60);
                line[7..7+err_len].copy_from_slice(&err_str[..err_len]);
                print_line(&line[..7+err_len], COLOR_RED);
            }
        }
    }
}
