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
use alloc::string::ToString;
use core::str;

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED, COLOR_ACCENT};
use crate::fs::ramfs;
use crate::shell::commands::utils::{trim_bytes, format_num_simple};

use super::cwd::{get_cwd, set_cwd};

pub fn cmd_cd(cmd: &[u8]) {
    let path = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        set_cwd("/home/anonymous");
        print_line(b"Changed to: /home/anonymous", COLOR_GREEN);
        return;
    };

    if path.is_empty() || path == b"~" {
        set_cwd("/home/anonymous");
        print_line(b"Changed to: /home/anonymous", COLOR_GREEN);
        return;
    }

    let path_str = match str::from_utf8(path) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"cd: invalid path encoding", COLOR_RED);
            return;
        }
    };

    let new_path = if path_str.starts_with('/') {
        String::from(path_str)
    } else if path_str == ".." {
        let cwd = get_cwd();
        cwd.rsplit_once('/').map(|(p, _)| if p.is_empty() { "/" } else { p }).unwrap_or("/").to_string()
    } else if path_str == "." {
        String::from(get_cwd())
    } else {
        let cwd = get_cwd();
        if cwd.ends_with('/') {
            alloc::format!("{}{}", cwd, path_str)
        } else {
            alloc::format!("{}/{}", cwd, path_str)
        }
    };

    set_cwd(&new_path);

    let mut line = [0u8; 80];
    line[..12].copy_from_slice(b"Changed to: ");
    let path_bytes = new_path.as_bytes();
    let path_len = path_bytes.len().min(60);
    line[12..12+path_len].copy_from_slice(&path_bytes[..path_len]);
    print_line(&line[..12+path_len], COLOR_GREEN);
}

pub fn cmd_pwd() {
    let cwd = get_cwd();
    let cwd_bytes = cwd.as_bytes();
    let cwd_len = cwd_bytes.len().min(60);
    let mut line = [0u8; 64];
    line[..cwd_len].copy_from_slice(&cwd_bytes[..cwd_len]);
    print_line(&line[..cwd_len], COLOR_TEXT);
}

pub fn cmd_tree(cmd: &[u8]) {
    let path = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        get_cwd().as_bytes()
    };

    let path_str = match str::from_utf8(path) {
        Ok(s) => if s.is_empty() { get_cwd() } else { s },
        Err(_) => {
            print_line(b"tree: invalid path encoding", COLOR_RED);
            return;
        }
    };

    let path_bytes = path_str.as_bytes();
    let path_len = path_bytes.len().min(60);
    let mut header = [0u8; 64];
    header[..path_len].copy_from_slice(&path_bytes[..path_len]);
    print_line(&header[..path_len], COLOR_ACCENT);

    let files = ramfs::list_files();
    let prefix = if path_str.ends_with('/') { path_str.to_string() } else { alloc::format!("{}/", path_str) };

    let mut count = 0;
    for file in files {
        if file.starts_with(&prefix) || (path_str == "/" && !file.is_empty()) {
            let rel_path = if path_str == "/" {
                &file[1..]
            } else {
                file.strip_prefix(&prefix).unwrap_or(&file)
            };

            let depth = rel_path.matches('/').count();
            let indent = depth * 4;

            let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len().min(50);

            let mut line = [0u8; 80];
            for i in 0..indent.min(20) {
                line[i] = b' ';
            }
            line[indent..indent+4].copy_from_slice(b"|-- ");
            line[indent+4..indent+4+name_len].copy_from_slice(&name_bytes[..name_len]);
            print_line(&line[..indent+4+name_len], COLOR_TEXT);
            count += 1;
        }
    }

    print_line(b"", COLOR_TEXT);
    let mut summary = [0u8; 48];
    let count_len = format_num_simple(&mut summary, count);
    summary[count_len..count_len+11].copy_from_slice(b" files/dirs");
    print_line(&summary[..count_len+11], COLOR_TEXT_DIM);
}
