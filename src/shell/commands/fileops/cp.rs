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
use crate::fs::ramfs;
use super::utils::{bytes_to_str, split_args};

pub fn cmd_cp(cmd: &[u8]) {
    let args = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        print_line(b"Usage: cp <source> <dest>", COLOR_TEXT_DIM);
        return;
    };

    let parts = split_args(args);
    if parts.len() < 2 {
        print_line(b"cp: source and destination required", COLOR_RED);
        return;
    }

    let source_str = match bytes_to_str(parts[0]) {
        Some(s) => s,
        None => {
            print_line(b"cp: invalid source path encoding", COLOR_RED);
            return;
        }
    };

    let dest_str = match bytes_to_str(parts[1]) {
        Some(s) => s,
        None => {
            print_line(b"cp: invalid destination path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::read_file(source_str) {
        Ok(data) => {
            match ramfs::create_file(dest_str, &data) {
                Ok(()) => {
                    let mut line = [0u8; 80];
                    line[..8].copy_from_slice(b"Copied: ");
                    let src_len = parts[0].len().min(30);
                    line[8..8+src_len].copy_from_slice(&parts[0][..src_len]);
                    line[8+src_len..8+src_len+4].copy_from_slice(b" -> ");
                    let dst_len = parts[1].len().min(30);
                    line[12+src_len..12+src_len+dst_len].copy_from_slice(&parts[1][..dst_len]);
                    print_line(&line[..12+src_len+dst_len], COLOR_GREEN);
                }
                Err(e) => {
                    let mut line = [0u8; 80];
                    line[..4].copy_from_slice(b"cp: ");
                    let err_str = e.as_str().as_bytes();
                    let err_len = err_str.len().min(60);
                    line[4..4+err_len].copy_from_slice(&err_str[..err_len]);
                    print_line(&line[..4+err_len], COLOR_RED);
                }
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..4].copy_from_slice(b"cp: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[4..4+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..4+err_len], COLOR_RED);
        }
    }
}
