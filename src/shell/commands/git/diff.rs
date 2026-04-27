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
use super::{index, objects, repo};
use crate::fs::ramfs;
use alloc::format;
use alloc::string::String;

pub fn cmd_diff(_args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    let staged = index::read_index(cwd);
    let mut out = String::new();
    for entry in &staged {
        let full = repo::repo_path(cwd, &entry.path);
        let current = ramfs::read_file(&full).unwrap_or_default();
        let stored = objects::read_object(cwd, &entry.hash).unwrap_or_default();
        if current != stored {
            out.push_str(&format!("diff --git a/{} b/{}\n", entry.path, entry.path));
            out.push_str("--- a/\n+++ b/\n");
            let old = core::str::from_utf8(&stored).unwrap_or("");
            let new = core::str::from_utf8(&current).unwrap_or("");
            for line in old.lines() {
                out.push_str(&format!("-{}\n", line));
            }
            for line in new.lines() {
                out.push_str(&format!("+{}\n", line));
            }
        }
    }
    if out.is_empty() {
        String::from("No changes")
    } else {
        out
    }
}
