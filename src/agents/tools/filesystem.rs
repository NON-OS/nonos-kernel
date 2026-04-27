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

use alloc::format;
use alloc::vec::Vec;

pub(super) fn register() {
    super::register_tool(b"shell", b"Execute shell command", tool_shell);
    super::register_tool(b"read_file", b"Read file contents", tool_read);
    super::register_tool(b"write_file", b"Write to file: path content", tool_write);
    super::register_tool(b"list_dir", b"List directory contents", tool_list);
}

fn tool_shell(args: &[u8]) -> Vec<u8> {
    crate::shell::execute_and_capture(args)
}

fn tool_read(args: &[u8]) -> Vec<u8> {
    let path = core::str::from_utf8(args).unwrap_or("").trim();
    crate::fs::ramfs::read_file(path)
        .unwrap_or_else(|_| format!("Cannot read: {}", path).into_bytes())
}

fn tool_write(args: &[u8]) -> Vec<u8> {
    let s = core::str::from_utf8(args).unwrap_or("");
    let (path, content) = s.split_once(' ').unwrap_or((s, ""));
    match crate::fs::ramfs::write_file(path.trim(), content.as_bytes()) {
        Ok(_) => format!("Written {} bytes to {}", content.len(), path).into_bytes(),
        Err(_) => format!("Failed to write to {}", path).into_bytes(),
    }
}

fn tool_list(args: &[u8]) -> Vec<u8> {
    let path = core::str::from_utf8(args).unwrap_or("/ram").trim();
    let path = if path.is_empty() { "/ram" } else { path };
    match crate::fs::ramfs::list_dir_entries(path) {
        Ok(entries) => {
            if entries.is_empty() {
                return format!("Directory {} is empty", path).into_bytes();
            }
            let mut out = format!("Contents of {}:\n", path);
            for e in entries {
                let kind = if e.is_dir { "dir " } else { "file" };
                out.push_str(&format!("  {} {}\n", kind, e.name));
            }
            out.into_bytes()
        }
        Err(_) => format!("Cannot list: {}", path).into_bytes(),
    }
}
