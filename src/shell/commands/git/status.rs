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
use super::{index, refs, repo};
use alloc::format;
use alloc::string::String;

pub fn cmd_status(_args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    let mut out = String::new();
    if let Some(branch) = repo::current_branch(cwd) {
        out.push_str(&format!("On branch {}\n", branch));
    }
    let staged = index::read_index(cwd);
    if staged.is_empty() {
        if refs::head_commit(cwd).is_none() {
            out.push_str("\nNo commits yet\n");
        }
        out.push_str("\nnothing to commit, working tree clean\n");
    } else {
        out.push_str("\nChanges to be committed:\n");
        for entry in &staged {
            out.push_str(&format!("  new file:   {}\n", entry.path));
        }
    }
    out
}
