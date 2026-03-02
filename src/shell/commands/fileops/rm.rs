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

use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_TEXT_DIM};
use crate::fs::{self, ramfs};
use super::utils::bytes_to_str;

pub fn cmd_rm(cmd: &[u8]) {
    let args = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        print_line(b"Usage: rm [-rf] <file>", COLOR_TEXT_DIM);
        return;
    };

    if args.is_empty() {
        print_line(b"rm: file name required", COLOR_RED);
        return;
    }

    let (recursive, force, path) = parse_rm_flags(args);

    if path.is_empty() {
        print_line(b"rm: file name required", COLOR_RED);
        return;
    }

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"rm: invalid path encoding", COLOR_RED);
            return;
        }
    };

    let is_dir = fs::is_directory(path_str);

    if is_dir && !recursive {
        print_line(b"rm: cannot remove directory without -r", COLOR_RED);
        return;
    }

    let result = if is_dir {
        rm_recursive(path_str)
    } else {
        fs::unlink(path_str)
    };

    match result {
        Ok(()) => {
            let mut line = [0u8; 64];
            if recursive {
                line[..20].copy_from_slice(b"Removed recursively: ");
                let path_len = path.len().min(40);
                line[20..20+path_len].copy_from_slice(&path[..path_len]);
                print_line(&line[..20+path_len], COLOR_YELLOW);
            } else {
                line[..9].copy_from_slice(b"Removed: ");
                let path_len = path.len().min(48);
                line[9..9+path_len].copy_from_slice(&path[..path_len]);
                print_line(&line[..9+path_len], COLOR_GREEN);
            }
            print_line(b"Data securely zeroed from RAM", COLOR_GREEN);
        }
        Err(e) => {
            if !force {
                let mut line = [0u8; 80];
                line[..4].copy_from_slice(b"rm: ");
                let err_bytes = e.as_bytes();
                let err_len = err_bytes.len().min(60);
                line[4..4+err_len].copy_from_slice(&err_bytes[..err_len]);
                print_line(&line[..4+err_len], COLOR_RED);
            }
        }
    }
}

fn parse_rm_flags(args: &[u8]) -> (bool, bool, &[u8]) {
    let mut recursive = false;
    let mut force = false;
    let mut rest = args;

    loop {
        if rest.starts_with(b"-rf ") || rest.starts_with(b"-fr ") {
            recursive = true;
            force = true;
            rest = trim_bytes(&rest[4..]);
        } else if rest.starts_with(b"-r ") || rest.starts_with(b"-R ") {
            recursive = true;
            rest = trim_bytes(&rest[3..]);
        } else if rest.starts_with(b"-f ") {
            force = true;
            rest = trim_bytes(&rest[3..]);
        } else if rest == b"-rf" || rest == b"-fr" {
            return (true, true, &[]);
        } else if rest == b"-r" || rest == b"-R" {
            return (true, false, &[]);
        } else if rest == b"-f" {
            return (false, true, &[]);
        } else {
            break;
        }
    }

    (recursive, force, rest)
}

fn rm_recursive(path: &str) -> Result<(), &'static str> {
    let entries = ramfs::list_dir(path).map_err(|e| e.as_str())?;

    for entry in entries {
        let entry_name = entry.trim_end_matches('/');
        let full_path = if path.ends_with('/') {
            alloc::format!("{}{}", path, entry_name)
        } else {
            alloc::format!("{}/{}", path, entry_name)
        };

        if entry.ends_with('/') {
            rm_recursive(&full_path)?;
        } else {
            fs::unlink(&full_path)?;
        }
    }

    fs::rmdir(path)
}
