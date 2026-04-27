// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::{config, github, repo};
use crate::fs::ramfs;
use crate::graphics::framebuffer::{COLOR_ERROR, COLOR_TEXT_DIM, COLOR_WHITE};
use crate::shell::output::print_line;
use alloc::format;
use alloc::string::String;

pub fn cmd_pull(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    if !crate::network::stack::is_network_available() {
        print_line(b"error: network not available", COLOR_ERROR);
        return String::from("fatal: unable to access network - check connection");
    }
    let remote = if args.is_empty() { "origin" } else { args[0] };
    let url = match config::get_remote_url(cwd, remote) {
        Some(u) => u,
        None => return format!("fatal: '{}' does not appear to be a git repository", remote),
    };
    let (owner, repo_name) = match github::parse_github_url(&url) {
        Some(p) => p,
        None => return String::from("error: only GitHub remotes supported for pull"),
    };
    print_line(format!("From {}", url).as_bytes(), COLOR_WHITE);
    let current = repo::current_branch(cwd);
    let branch = current.as_deref().unwrap_or("main");
    print_line(format!(" * branch            {} -> FETCH_HEAD", branch).as_bytes(), COLOR_WHITE);
    print_line(b"Fetching tree...", COLOR_TEXT_DIM);
    crate::time::yield_now();
    match github::fetch_repo_tree_with_timeout(&owner, &repo_name, branch, 10000) {
        Ok(tree) => {
            print_line(format!("Found {} entries", tree.len()).as_bytes(), COLOR_TEXT_DIM);
            let mut files = 0;
            for (i, (path, is_dir)) in tree.iter().enumerate() {
                let full = repo::repo_path(cwd, path);
                if *is_dir {
                    let _ = ramfs::create_dir(&full);
                } else {
                    if i % 5 == 0 {
                        crate::time::yield_now();
                    }
                    if let Ok(data) =
                        github::fetch_file_with_timeout(&owner, &repo_name, branch, path, 5000)
                    {
                        let _ = ramfs::create_file(&full, &data);
                        files += 1;
                        if files % 10 == 0 {
                            print_line(format!("  {} files...", files).as_bytes(), COLOR_TEXT_DIM);
                        }
                    }
                }
            }
            format!("Updating complete: {} files received", files)
        }
        Err(e) => {
            print_line(format!("error: {}", e).as_bytes(), COLOR_ERROR);
            format!("error: {}", e)
        }
    }
}
