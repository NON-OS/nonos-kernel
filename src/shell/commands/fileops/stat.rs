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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_stat(cmd: &[u8]) {
    let path = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: stat <file>", COLOR_TEXT_DIM);
        return;
    };

    if path.is_empty() {
        print_line(b"stat: file required", COLOR_RED);
        return;
    }

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"stat: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::NONOS_FILESYSTEM.get_file_info(path_str) {
        Ok(info) => {
            let mut line = [0u8; 64];
            line[..8].copy_from_slice(b"  File: ");
            let path_len = path.len().min(48);
            line[8..8+path_len].copy_from_slice(&path[..path_len]);
            print_line(&line[..8+path_len], COLOR_TEXT_WHITE);

            let mut size_line = [0u8; 48];
            size_line[..8].copy_from_slice(b"  Size: ");
            let size_len = format_num_simple(&mut size_line[8..], info.size);
            size_line[8+size_len..8+size_len+14].copy_from_slice(b"          Blocks: 0");
            print_line(&size_line[..8+size_len+14], COLOR_TEXT);

            print_line(b"Device: ramfs      Inode: 1", COLOR_TEXT);

            if info.encrypted {
                print_line(b"Encryption: ENABLED (AES-256-GCM)", COLOR_GREEN);
            } else {
                print_line(b"Encryption: disabled", COLOR_TEXT_DIM);
            }

            print_line(b"Access: (0644/-rw-r--r--)", COLOR_TEXT);
            print_line(b"   Uid: (0/anonymous)  Gid: (0/root)", COLOR_TEXT);

            let mut created_line = [0u8; 48];
            created_line[..9].copy_from_slice(b"Created: ");
            let created_len = format_num_simple(&mut created_line[9..], info.created as usize);
            created_line[9+created_len..9+created_len+7].copy_from_slice(b" ticks");
            print_line(&created_line[..16+created_len], COLOR_TEXT_DIM);

            let mut modified_line = [0u8; 48];
            modified_line[..10].copy_from_slice(b"Modified: ");
            let modified_len = format_num_simple(&mut modified_line[10..], info.modified as usize);
            modified_line[10+modified_len..10+modified_len+7].copy_from_slice(b" ticks");
            print_line(&modified_line[..17+modified_len], COLOR_TEXT_DIM);
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..6].copy_from_slice(b"stat: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[6..6+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..6+err_len], COLOR_RED);
        }
    }
}
