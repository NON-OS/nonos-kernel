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

pub fn cmd_add(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    if args.is_empty() {
        return String::from("Nothing specified, nothing added.");
    }
    let mut added = 0;
    for &path in args {
        let full =
            if path.starts_with('/') { String::from(path) } else { repo::repo_path(cwd, path) };
        if let Ok(data) = ramfs::read_file(&full) {
            match objects::store_blob(cwd, &data) {
                Ok(hash) => {
                    if index::add_to_index(cwd, path, &hash).is_ok() {
                        added += 1;
                    }
                }
                Err(e) => return format!("error: {}", e),
            }
        } else {
            return format!("fatal: pathspec '{}' did not match any files", path);
        }
    }
    format!("Added {} file(s) to staging area", added)
}
