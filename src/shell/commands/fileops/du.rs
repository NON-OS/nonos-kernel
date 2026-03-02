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
use alloc::vec::Vec;
use crate::shell::output::print_line;
use crate::shell::commands::utils::format_num_simple;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};
use crate::fs::ramfs;

pub fn cmd_du(_cmd: &[u8]) {
    print_line(b"Disk Usage (RAM):", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let stats = ramfs::stats();
    let files = ramfs::list_files();

    let mut dirs: Vec<(String, usize)> = Vec::new();
    let mut total_size: usize = 0;

    for file in &files {
        if let Ok(info) = ramfs::NONOS_FILESYSTEM.get_file_info(file) {
            total_size += info.size;

            let dir = file.rsplit_once('/').map(|(d, _)| d).unwrap_or("/");
            if let Some(entry) = dirs.iter_mut().find(|(d, _)| d == dir) {
                entry.1 += info.size;
            } else {
                dirs.push((String::from(dir), info.size));
            }
        }
    }

    for (dir, size) in &dirs {
        let mut line = [0u8; 64];
        let size_len = format_num_simple(&mut line, *size);
        line[size_len] = b'\t';
        let dir_bytes = dir.as_bytes();
        let dir_len = dir_bytes.len().min(48);
        line[size_len+1..size_len+1+dir_len].copy_from_slice(&dir_bytes[..dir_len]);
        print_line(&line[..size_len+1+dir_len], COLOR_TEXT);
    }

    let mut total_line = [0u8; 48];
    let total_len = format_num_simple(&mut total_line, total_size);
    total_line[total_len..total_len+7].copy_from_slice(b"\ttotal");
    print_line(&total_line[..total_len+7], COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Note: All storage in RAM (ZeroState)", COLOR_YELLOW);

    let mut stats_line = [0u8; 48];
    stats_line[..7].copy_from_slice(b"Files: ");
    let files_len = format_num_simple(&mut stats_line[7..], stats.files as usize);
    print_line(&stats_line[..7+files_len], COLOR_TEXT_DIM);
}
