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
use super::{refs, repo};
use alloc::format;
use alloc::string::String;

pub fn cmd_branch(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    if args.is_empty() {
        let branches = refs::list_branches(cwd);
        let current = repo::current_branch(cwd);
        let mut out = String::new();
        for b in branches {
            let marker = if Some(&b) == current.as_ref() { "* " } else { "  " };
            out.push_str(&format!("{}{}\n", marker, b));
        }
        return if out.is_empty() { String::from("No branches yet") } else { out };
    }
    let name = args[0];
    if args.contains(&"-d") || args.contains(&"-D") {
        let ref_path = format!("{}/{}", repo::REFS_HEADS, name);
        if crate::fs::ramfs::delete(&repo::repo_path(cwd, &ref_path)).is_ok() {
            return format!("Deleted branch {}", name);
        }
        return format!("error: branch '{}' not found", name);
    }
    if let Some(head) = refs::head_commit(cwd) {
        let ref_path = format!("{}/{}", repo::REFS_HEADS, name);
        if refs::write_ref(cwd, &ref_path, &head).is_ok() {
            return format!("Created branch {}", name);
        }
    }
    String::from("error: failed to create branch")
}
