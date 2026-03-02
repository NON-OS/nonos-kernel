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

pub fn cmd_ln(cmd: &[u8]) {
    let args = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        print_line(b"Usage: ln [-s] <target> <link>", COLOR_TEXT_DIM);
        return;
    };

    let (symbolic, rest) = if args.starts_with(b"-s ") {
        (true, trim_bytes(&args[3..]))
    } else {
        (false, args)
    };

    let parts = split_args(rest);
    if parts.len() < 2 {
        print_line(b"ln: target and link name required", COLOR_RED);
        return;
    }

    let target_str = match bytes_to_str(parts[0]) {
        Some(s) => s,
        None => {
            print_line(b"ln: invalid target path encoding", COLOR_RED);
            return;
        }
    };

    let link_str = match bytes_to_str(parts[1]) {
        Some(s) => s,
        None => {
            print_line(b"ln: invalid link path encoding", COLOR_RED);
            return;
        }
    };

    let result = if symbolic {
        fs::symlink(target_str, link_str)
    } else {
        fs::link(target_str, link_str)
    };

    match result {
        Ok(()) => {
            let mut line = [0u8; 80];
            if symbolic {
                line[..17].copy_from_slice(b"Created symlink: ");
                let link_len = parts[1].len().min(25);
                line[17..17+link_len].copy_from_slice(&parts[1][..link_len]);
                line[17+link_len..17+link_len+4].copy_from_slice(b" -> ");
                let tgt_len = parts[0].len().min(25);
                line[21+link_len..21+link_len+tgt_len].copy_from_slice(&parts[0][..tgt_len]);
                print_line(&line[..21+link_len+tgt_len], COLOR_GREEN);
            } else {
                line[..18].copy_from_slice(b"Created hardlink: ");
                let link_len = parts[1].len().min(30);
                line[18..18+link_len].copy_from_slice(&parts[1][..link_len]);
                print_line(&line[..18+link_len], COLOR_GREEN);
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..4].copy_from_slice(b"ln: ");
            let err_bytes = e.as_bytes();
            let err_len = err_bytes.len().min(60);
            line[4..4+err_len].copy_from_slice(&err_bytes[..err_len]);
            print_line(&line[..4+err_len], COLOR_RED);
        }
    }
}
