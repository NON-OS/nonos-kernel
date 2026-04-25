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
use super::{objects, refs, repo};
use alloc::format;
use alloc::string::String;

pub fn cmd_log(_args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    let mut out = String::new();
    let mut current = refs::head_commit(cwd);
    let mut count = 0;
    while let Some(hash) = current {
        if count >= 20 {
            break;
        }
        if let Ok(data) = objects::read_object(cwd, &hash) {
            if let Some((_, parent, msg)) = objects::parse_commit(&data) {
                out.push_str(&format!("commit {}\n    {}\n\n", hash, msg));
                current = parent;
                count += 1;
                continue;
            }
        }
        break;
    }
    if out.is_empty() {
        String::from("No commits yet")
    } else {
        out
    }
}
