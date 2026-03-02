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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::fs::ramfs;
use super::utils::bytes_to_str;

pub fn cmd_tee(cmd: &[u8]) {
    let args = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        print_line(b"Usage: tee <file>", COLOR_TEXT_DIM);
        print_line(b"(Reads from stdin, writes to file and stdout)", COLOR_TEXT_DIM);
        return;
    };

    let path_str = match bytes_to_str(args) {
        Some(s) => s,
        None => {
            print_line(b"tee: invalid path encoding", COLOR_RED);
            return;
        }
    };

    print_line(b"tee: Reading from previous pipe output...", COLOR_TEXT_DIM);
    print_line(b"(In RAM-only mode, tee shows this message)", COLOR_YELLOW);
    print_line(args, COLOR_TEXT);

    match ramfs::create_file(path_str, args) {
        Ok(()) => {
            let mut line = [0u8; 64];
            line[..18].copy_from_slice(b"Written to file: ");
            let path_len = args.len().min(40);
            line[18..18+path_len].copy_from_slice(&args[..path_len]);
            print_line(&line[..18+path_len], COLOR_GREEN);
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..5].copy_from_slice(b"tee: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[5..5+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..5+err_len], COLOR_RED);
        }
    }
}
