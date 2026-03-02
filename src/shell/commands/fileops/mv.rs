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
use super::utils::{bytes_to_str, split_args};

pub fn cmd_mv(cmd: &[u8]) {
    let args = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        print_line(b"Usage: mv <source> <dest>", COLOR_TEXT_DIM);
        return;
    };

    let parts = split_args(args);
    if parts.len() < 2 {
        print_line(b"mv: source and destination required", COLOR_RED);
        return;
    }

    let source_str = match bytes_to_str(parts[0]) {
        Some(s) => s,
        None => {
            print_line(b"mv: invalid source path encoding", COLOR_RED);
            return;
        }
    };

    let dest_str = match bytes_to_str(parts[1]) {
        Some(s) => s,
        None => {
            print_line(b"mv: invalid destination path encoding", COLOR_RED);
            return;
        }
    };

    match fs::rename(source_str, dest_str) {
        Ok(()) => {
            let mut line = [0u8; 80];
            line[..7].copy_from_slice(b"Moved: ");
            let src_len = parts[0].len().min(30);
            line[7..7+src_len].copy_from_slice(&parts[0][..src_len]);
            line[7+src_len..7+src_len+4].copy_from_slice(b" -> ");
            let dst_len = parts[1].len().min(30);
            line[11+src_len..11+src_len+dst_len].copy_from_slice(&parts[1][..dst_len]);
            print_line(&line[..11+src_len+dst_len], COLOR_GREEN);
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..4].copy_from_slice(b"mv: ");
            let err_bytes = e.as_bytes();
            let err_len = err_bytes.len().min(60);
            line[4..4+err_len].copy_from_slice(&err_bytes[..err_len]);
            print_line(&line[..4+err_len], COLOR_RED);
        }
    }
}
