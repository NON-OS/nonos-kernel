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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED};
use crate::fs::ramfs;
use super::utils::{bytes_to_str, find_subsequence};

pub fn cmd_find(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: find <path> [-name <pattern>]", COLOR_TEXT_DIM);
        return;
    };

    let (search_path, pattern) = parse_find_args(args);

    let path_str = match bytes_to_str(search_path) {
        Some(s) => if s.is_empty() { "/" } else { s },
        None => {
            print_line(b"find: invalid path encoding", COLOR_RED);
            return;
        }
    };

    print_line(b"Searching RAM filesystem...", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);

    let files = ramfs::list_files();
    let mut found = 0;

    for file in files {
        if !file.starts_with(path_str) && path_str != "/" {
            continue;
        }

        if let Some(pat) = pattern {
            let file_name = file.rsplit('/').next().unwrap_or(&file);
            if !matches_pattern(file_name.as_bytes(), pat) {
                continue;
            }
        }

        let file_bytes = file.as_bytes();
        let line_len = file_bytes.len().min(60);
        let mut output = [0u8; 64];
        output[..line_len].copy_from_slice(&file_bytes[..line_len]);
        print_line(&output[..line_len], COLOR_TEXT);
        found += 1;
    }

    if found == 0 {
        print_line(b"(no matching files)", COLOR_TEXT_DIM);
    } else {
        print_line(b"", COLOR_TEXT);
        let mut line = [0u8; 32];
        let len = format_num_simple(&mut line, found);
        line[len..len+13].copy_from_slice(b" files found");
        print_line(&line[..len+13], COLOR_GREEN);
    }
}

fn parse_find_args(args: &[u8]) -> (&[u8], Option<&[u8]>) {
    if let Some(pos) = find_subsequence(args, b"-name ") {
        let path = trim_bytes(&args[..pos]);
        let pattern = trim_bytes(&args[pos+6..]);
        (path, Some(pattern))
    } else {
        (args, None)
    }
}

fn matches_pattern(name: &[u8], pattern: &[u8]) -> bool {
    if pattern == b"*" {
        return true;
    }

    if pattern.starts_with(b"*") && pattern.ends_with(b"*") {
        let middle = &pattern[1..pattern.len()-1];
        return find_subsequence(name, middle).is_some();
    }

    if pattern.starts_with(b"*") {
        let suffix = &pattern[1..];
        return name.ends_with(suffix);
    }

    if pattern.ends_with(b"*") {
        let prefix = &pattern[..pattern.len()-1];
        return name.starts_with(prefix);
    }

    name == pattern
}
