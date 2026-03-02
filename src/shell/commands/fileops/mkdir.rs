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
use crate::graphics::framebuffer::{COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::fs;
use super::utils::bytes_to_str;

pub fn cmd_mkdir(cmd: &[u8]) {
    let path = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: mkdir <directory>", COLOR_TEXT_DIM);
        return;
    };

    if path.is_empty() {
        print_line(b"mkdir: directory name required", COLOR_RED);
        return;
    }

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"mkdir: invalid path encoding", COLOR_RED);
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

    match fs::mkdir(&full_path, 0o755) {
        Ok(()) => {
            let mut line = [0u8; 80];
            let prefix = b"Created directory: ";
            let prefix_len = prefix.len();
            line[..prefix_len].copy_from_slice(prefix);
            let path_bytes = full_path.as_bytes();
            let path_len = path_bytes.len().min(80 - prefix_len);
            line[prefix_len..prefix_len+path_len].copy_from_slice(&path_bytes[..path_len]);
            print_line(&line[..prefix_len+path_len], COLOR_GREEN);
            print_line(b"(RAM filesystem - erased on shutdown)", COLOR_YELLOW);
        }
        Err(e) => {
            let mut line = [0u8; 80];
            let prefix = b"mkdir: ";
            let prefix_len = prefix.len();
            line[..prefix_len].copy_from_slice(prefix);
            let err_bytes = e.as_bytes();
            let err_len = err_bytes.len().min(80 - prefix_len);
            line[prefix_len..prefix_len+err_len].copy_from_slice(&err_bytes[..err_len]);
            print_line(&line[..prefix_len+err_len], COLOR_RED);
        }
    }
}
