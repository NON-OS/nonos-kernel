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

pub fn cmd_pull(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) { return String::from("fatal: not a git repository"); }
    let remote = if args.is_empty() { "origin" } else { args[0] };
    let url = match config::get_remote_url(cwd, remote) {
        Some(u) => u, None => return format!("fatal: '{}' does not appear to be a git repository", remote),
    };
    let (owner, repo_name) = match github::parse_github_url(&url) {
        Some(p) => p, None => return String::from("error: only GitHub remotes supported for pull"),
    };
    let mut out = format!("From {}\n", url);
    let current = repo::current_branch(cwd);
    let branch = current.as_deref().unwrap_or("main");
    out.push_str(&format!(" * branch            {} -> FETCH_HEAD\n", branch));
    match github::fetch_repo_tree(&owner, &repo_name, branch) {
        Ok(tree) => {
            let mut files = 0;
            for (path, is_dir) in &tree {
                let full = repo::repo_path(cwd, path);
                if *is_dir { let _ = ramfs::create_dir(&full); }
                else if let Ok(data) = github::fetch_file(&owner, &repo_name, branch, path) {
                    let _ = ramfs::create_file(&full, &data);
                    files += 1;
                }
            }
            out.push_str(&format!("Updating... {} files received\n", files));
        }
        Err(e) => out.push_str(&format!("error: {}\n", e)),
    }
    out
}
