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
use super::{index, objects, refs, repo};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub fn cmd_commit(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    let msg = parse_message(args);
    if msg.is_empty() {
        return String::from("Aborting commit due to empty commit message.");
    }
    let staged = index::read_index(cwd);
    if staged.is_empty() {
        return String::from("nothing to commit, working tree clean");
    }
    let tree_entries: Vec<(String, String)> =
        staged.iter().map(|e| (e.path.clone(), e.hash.clone())).collect();
    let tree = match objects::store_tree(cwd, &tree_entries) {
        Ok(h) => h,
        Err(e) => return format!("error: {}", e),
    };
    let parent = refs::head_commit(cwd);
    let commit = match objects::store_commit(cwd, &tree, parent.as_deref(), &msg) {
        Ok(h) => h,
        Err(e) => return format!("error: {}", e),
    };
    if let Some(head) = refs::read_head(cwd) {
        if head.starts_with("refs/") {
            let _ = refs::write_ref(cwd, &head, &commit);
        }
    }
    let _ = index::clear_index(cwd);
    format!("[{}] {}", &commit[..8], msg)
}

fn parse_message(args: &[&str]) -> String {
    for i in 0..args.len() {
        if args[i] == "-m" && i + 1 < args.len() {
            return String::from(args[i + 1]);
        }
    }
    String::new()
}
