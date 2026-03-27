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
use alloc::string::String;
use alloc::format;
use crate::fs::ramfs;
use super::{repo, config, github};

pub fn cmd_clone(args: &[&str], cwd: &str) -> String {
    if args.is_empty() { return String::from("usage: git clone <url> [<directory>]"); }
    let url = args[0];
    let (owner, repo_name) = match github::parse_github_url(url) {
        Some(p) => p, None => return String::from("error: only GitHub URLs supported"),
    };
    let dir_name = if args.len() > 1 { String::from(args[1]) } else { repo_name.clone() };
    let target = repo::repo_path(cwd, &dir_name);
    if ramfs::exists(&target) { return format!("fatal: '{}' already exists", dir_name); }
    if ramfs::create_dir(&target).is_err() { return String::from("fatal: mkdir failed"); }
    if repo::init(&target).is_err() { return String::from("fatal: init failed"); }
    let _ = config::set_remote_url(&target, "origin", url);
    let mut out = format!("Cloning into '{}'...\n", dir_name);
    match github::fetch_repo_tree(&owner, &repo_name, "main") {
        Ok(tree) => {
            out.push_str(&format!("remote: Counting objects: {}\n", tree.len()));
            let mut files = 0;
            for (path, is_dir) in &tree {
                let full = repo::repo_path(&target, path);
                if *is_dir { let _ = ramfs::create_dir(&full); }
                else if let Ok(data) = github::fetch_file(&owner, &repo_name, "main", path) {
                    let _ = ramfs::create_file(&full, &data);
                    files += 1;
                }
            }
            out.push_str(&format!("Receiving objects: 100% ({}/{}), done.\n", files, tree.len()));
        }
        Err(e) => out.push_str(&format!("warning: {}, repo initialized empty\n", e)),
    }
    out
}
