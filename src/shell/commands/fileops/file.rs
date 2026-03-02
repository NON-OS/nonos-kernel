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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_file(cmd: &[u8]) {
    let path = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: file <filename>", COLOR_TEXT_DIM);
        return;
    };

    if path.is_empty() {
        print_line(b"file: filename required", COLOR_RED);
        return;
    }

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"file: invalid path encoding", COLOR_RED);
            return;
        }
    };

    if !ramfs::exists(path_str) {
        let mut line = [0u8; 64];
        let path_len = path.len().min(30);
        line[..path_len].copy_from_slice(&path[..path_len]);
        line[path_len..path_len+18].copy_from_slice(b": cannot stat file");
        print_line(&line[..path_len+18], COLOR_RED);
        return;
    }

    let mut line = [0u8; 64];
    let path_len = path.len().min(30);
    line[..path_len].copy_from_slice(&path[..path_len]);
    line[path_len..path_len+2].copy_from_slice(b": ");

    let ext_start = path.iter().rposition(|&c| c == b'.').unwrap_or(0);
    let file_type: &[u8] = if ext_start > 0 {
        match &path[ext_start..] {
            b".rs" => b"Rust source code",
            b".c" | b".h" => b"C source code",
            b".txt" => b"ASCII text",
            b".sh" => b"Shell script",
            b".conf" | b".config" => b"Configuration file",
            b".key" => b"Private key data (SENSITIVE)",
            b".pub" => b"Public key data",
            b".enc" => b"Encrypted data (AES-256-GCM)",
            b".sig" => b"Digital signature",
            _ => b"Regular file",
        }
    } else {
        b"Regular file"
    };

    let type_len = file_type.len();
    line[path_len+2..path_len+2+type_len].copy_from_slice(file_type);
    print_line(&line[..path_len+2+type_len], COLOR_TEXT);
}
