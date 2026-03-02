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
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::fs;
use super::utils::bytes_to_str;

pub fn cmd_rmdir(cmd: &[u8]) {
    let path = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: rmdir <directory>", COLOR_TEXT_DIM);
        return;
    };

    if path.is_empty() {
        print_line(b"rmdir: directory name required", COLOR_RED);
        return;
    }

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"rmdir: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match fs::rmdir(path_str) {
        Ok(()) => {
            let mut line = [0u8; 64];
            line[..18].copy_from_slice(b"Removed directory: ");
            let path_len = path.len().min(40);
            line[18..18+path_len].copy_from_slice(&path[..path_len]);
            print_line(&line[..18+path_len], COLOR_GREEN);
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..8].copy_from_slice(b"rmdir: ");
            let err_bytes = e.as_bytes();
            let err_len = err_bytes.len().min(60);
            line[8..8+err_len].copy_from_slice(&err_bytes[..err_len]);
            print_line(&line[..8+err_len], COLOR_RED);
        }
    }
}
