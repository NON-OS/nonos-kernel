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
use super::{config, github, repo};
use crate::fs::ramfs;
use alloc::format;
use alloc::string::String;

pub fn cmd_clone(args: &[&str], cwd: &str) -> String {
    if args.is_empty() {
        return String::from("usage: git clone <url> [<directory>]");
    }
    let url = args[0];
    let (_owner, repo_name) = match github::parse_github_url(url) {
        Some(p) => p,
        None => {
            let name = url.rsplit('/').next().unwrap_or("repo").trim_end_matches(".git");
            return clone_local(url, name, cwd);
        }
    };
    let dir_name = if args.len() > 1 { String::from(args[1]) } else { repo_name.clone() };
    let target = repo::repo_path(cwd, &dir_name);
    if ramfs::exists(&target) {
        return format!("fatal: '{}' already exists", dir_name);
    }
    if ramfs::create_dir(&target).is_err() {
        return String::from("fatal: mkdir failed");
    }
    if repo::init(&target).is_err() {
        return String::from("fatal: init failed");
    }
    let _ = config::set_remote_url(&target, "origin", url);
    format!("Cloning into '{}'...\nInitialized empty repository with remote 'origin'\nUse 'cd {}' then 'git pull' to fetch", dir_name, dir_name)
}

fn clone_local(url: &str, name: &str, cwd: &str) -> String {
    let target = repo::repo_path(cwd, name);
    if ramfs::exists(&target) {
        return format!("fatal: '{}' already exists", name);
    }
    if ramfs::create_dir(&target).is_err() {
        return String::from("fatal: mkdir failed");
    }
    if repo::init(&target).is_err() {
        return String::from("fatal: init failed");
    }
    let _ = config::set_remote_url(&target, "origin", url);
    format!("Initialized empty repository '{}' with remote '{}'", name, url)
}
