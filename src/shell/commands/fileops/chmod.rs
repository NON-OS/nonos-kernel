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

pub fn cmd_chmod(cmd: &[u8]) {
    let args = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: chmod <mode> <file>", COLOR_TEXT_DIM);
        print_line(b"Example: chmod 755 script.sh", COLOR_TEXT_DIM);
        return;
    };

    let parts = split_args(args);
    if parts.len() < 2 {
        print_line(b"chmod: mode and file required", COLOR_RED);
        return;
    }

    let mode_str = match bytes_to_str(parts[0]) {
        Some(s) => s,
        None => {
            print_line(b"chmod: invalid mode", COLOR_RED);
            return;
        }
    };

    let mode = match parse_octal_mode(mode_str) {
        Some(m) => m,
        None => {
            print_line(b"chmod: invalid mode format (use octal)", COLOR_RED);
            return;
        }
    };

    let path_str = match bytes_to_str(parts[1]) {
        Some(s) => s,
        None => {
            print_line(b"chmod: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match fs::chmod(path_str, mode) {
        Ok(()) => {
            let mut line = [0u8; 64];
            line[..13].copy_from_slice(b"Changed mode ");
            let file_len = parts[1].len().min(30);
            line[13..13+file_len].copy_from_slice(&parts[1][..file_len]);
            line[13+file_len..13+file_len+4].copy_from_slice(b" to ");
            let mode_len = parts[0].len().min(10);
            line[17+file_len..17+file_len+mode_len].copy_from_slice(&parts[0][..mode_len]);
            print_line(&line[..17+file_len+mode_len], COLOR_GREEN);
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..7].copy_from_slice(b"chmod: ");
            let err_bytes = e.as_bytes();
            let err_len = err_bytes.len().min(60);
            line[7..7+err_len].copy_from_slice(&err_bytes[..err_len]);
            print_line(&line[..7+err_len], COLOR_RED);
        }
    }
}

fn parse_octal_mode(s: &str) -> Option<u32> {
    let mut mode: u32 = 0;
    for c in s.chars() {
        if c < '0' || c > '7' {
            return None;
        }
        mode = mode * 8 + (c as u32 - '0' as u32);
    }
    Some(mode)
}
