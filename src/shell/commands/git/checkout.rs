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

pub fn cmd_checkout(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    if args.is_empty() {
        return String::from("error: no branch specified");
    }
    let name = args[0];
    let create = args.contains(&"-b");
    if create {
        if let Some(head) = refs::head_commit(cwd) {
            let ref_path = format!("{}/{}", repo::REFS_HEADS, name);
            if refs::write_ref(cwd, &ref_path, &head).is_err() {
                return String::from("error: failed to create branch");
            }
        }
    }
    let ref_path = format!("refs/heads/{}", name);
    if refs::read_ref(cwd, &ref_path).is_none() {
        return format!("error: pathspec '{}' did not match any branch", name);
    }
    if refs::write_head(cwd, &ref_path).is_ok() {
        format!("Switched to branch '{}'", name)
    } else {
        String::from("error: failed to switch branch")
    }
}
