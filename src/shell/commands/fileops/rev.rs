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
use core::str;
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_rev(cmd: &[u8]) {
    let path = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        print_line(b"Usage: rev <file>", COLOR_TEXT_DIM);
        return;
    };

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"rev: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::read_file(path_str) {
        Ok(data) => {
            let content = match str::from_utf8(&data) {
                Ok(s) => s,
                Err(_) => {
                    print_line(b"rev: file is not valid UTF-8 text", COLOR_RED);
                    return;
                }
            };

            for line in content.lines() {
                let reversed: String = line.chars().rev().collect();
                let bytes = reversed.as_bytes();
                let len = bytes.len().min(80);
                let mut output = [0u8; 80];
                output[..len].copy_from_slice(&bytes[..len]);
                print_line(&output[..len], COLOR_TEXT);
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..5].copy_from_slice(b"rev: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[5..5+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..5+err_len], COLOR_RED);
        }
    }
}
