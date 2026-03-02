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

use core::str;
use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_YELLOW, COLOR_RED, COLOR_ACCENT};
use crate::fs::ramfs;
use crate::shell::commands::utils::{trim_bytes, format_num_simple};

use super::cwd::get_cwd;

pub fn cmd_ls(cmd: &[u8]) {
    let args = if cmd.len() > 3 {
        trim_bytes(&cmd[3..])
    } else {
        b"" as &[u8]
    };

    let (show_all, show_long, path) = parse_ls_flags(args);

    let dir_path = if path.is_empty() {
        get_cwd()
    } else {
        match str::from_utf8(path) {
            Ok(s) => s,
            Err(_) => {
                print_line(b"ls: invalid path encoding", COLOR_RED);
                return;
            }
        }
    };

    let mut header = [0u8; 64];
    header[..11].copy_from_slice(b"Directory: ");
    let dir_bytes = dir_path.as_bytes();
    let dir_len = dir_bytes.len().min(48);
    header[11..11+dir_len].copy_from_slice(&dir_bytes[..dir_len]);
    print_line(&header[..11+dir_len], COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    match ramfs::list_dir(dir_path) {
        Ok(entries) => {
            if entries.is_empty() {
                print_line(b"(empty directory)", COLOR_TEXT_DIM);
            } else {
                for entry in entries {
                    if !show_all && entry.starts_with('.') {
                        continue;
                    }

                    let is_dir = entry.ends_with('/');
                    let entry_name = entry.trim_end_matches('/');

                    if show_long {
                        format_long_listing(entry_name, is_dir);
                    } else {
                        let entry_bytes = entry_name.as_bytes();
                        let entry_len = entry_bytes.len().min(60);
                        let mut line = [0u8; 64];
                        line[..entry_len].copy_from_slice(&entry_bytes[..entry_len]);

                        if is_dir {
                            line[entry_len] = b'/';
                            print_line(&line[..entry_len+1], COLOR_ACCENT);
                        } else {
                            print_line(&line[..entry_len], COLOR_TEXT);
                        }
                    }
                }
            }
        }
        Err(_e) => {
            let files = ramfs::list_files();
            let prefix = if dir_path.ends_with('/') { dir_path.to_string() } else { alloc::format!("{}/", dir_path) };

            let mut found = false;
            for file in files {
                if file.starts_with(&prefix) || (dir_path == "/" && !file.is_empty()) {
                    if !show_all && file.contains("/.") {
                        continue;
                    }

                    let rel_path = if dir_path == "/" {
                        &file[1..]
                    } else {
                        file.strip_prefix(&prefix).unwrap_or(&file)
                    };

                    let display_name = rel_path.split('/').next().unwrap_or(rel_path);
                    let is_dir = rel_path.contains('/');

                    if show_long {
                        format_long_listing(display_name, is_dir);
                    } else {
                        let display_bytes = display_name.as_bytes();
                        let display_len = display_bytes.len().min(60);
                        let mut line = [0u8; 64];
                        line[..display_len].copy_from_slice(&display_bytes[..display_len]);

                        if is_dir {
                            line[display_len] = b'/';
                            print_line(&line[..display_len+1], COLOR_ACCENT);
                        } else {
                            print_line(&line[..display_len], COLOR_TEXT);
                        }
                    }
                    found = true;
                }
            }

            if !found {
                print_line(b"(empty directory)", COLOR_TEXT_DIM);
            }
        }
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"All files in RAM (ZeroState)", COLOR_YELLOW);
}

fn parse_ls_flags(args: &[u8]) -> (bool, bool, &[u8]) {
    let mut show_all = false;
    let mut show_long = false;
    let mut rest = args;

    loop {
        if rest.starts_with(b"-la ") || rest.starts_with(b"-al ") {
            show_all = true;
            show_long = true;
            rest = trim_bytes(&rest[4..]);
        } else if rest.starts_with(b"-l ") {
            show_long = true;
            rest = trim_bytes(&rest[3..]);
        } else if rest.starts_with(b"-a ") {
            show_all = true;
            rest = trim_bytes(&rest[3..]);
        } else if rest == b"-la" || rest == b"-al" {
            return (true, true, &[]);
        } else if rest == b"-l" {
            return (false, true, &[]);
        } else if rest == b"-a" {
            return (true, false, &[]);
        } else {
            break;
        }
    }

    (show_all, show_long, rest)
}

fn format_long_listing(name: &str, is_dir: bool) {
    let mut line = [0u8; 80];

    if is_dir {
        line[..10].copy_from_slice(b"drwxr-x---");
    } else {
        line[..10].copy_from_slice(b"-rw-r-----");
    }

    line[10..12].copy_from_slice(b"  ");
    line[12..21].copy_from_slice(b"anonymous");
    line[21..23].copy_from_slice(b"  ");

    let size = if is_dir { 0 } else {
        ramfs::NONOS_FILESYSTEM.get_file_info(name)
            .map(|i| i.size)
            .unwrap_or(0)
    };

    let size_len = format_num_simple(&mut line[23..], size);
    let pos = 23 + size_len;

    line[pos..pos+2].copy_from_slice(b"  ");

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(40);
    line[pos+2..pos+2+name_len].copy_from_slice(&name_bytes[..name_len]);

    let total_len = pos + 2 + name_len;
    let color = if is_dir { COLOR_ACCENT } else { COLOR_TEXT };
    print_line(&line[..total_len], color);
}

use alloc::string::ToString;
