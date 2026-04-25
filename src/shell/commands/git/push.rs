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
use super::{config, refs, repo};
use alloc::format;
use alloc::string::String;

pub fn cmd_push(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    let remote = if args.is_empty() { "origin" } else { args[0] };
    let current = repo::current_branch(cwd);
    let branch = if args.len() > 1 { args[1] } else { current.as_deref().unwrap_or("main") };
    let url = match config::get_remote_url(cwd, remote) {
        Some(u) => u,
        None => return format!("fatal: '{}' does not appear to be a git repository", remote),
    };
    let head = match refs::head_commit(cwd) {
        Some(h) => h,
        None => return String::from("error: no commits to push"),
    };
    format!(
        "To {}\n   {}..{} {} -> {}/{}\nPush successful",
        url,
        &head[..7],
        &head[..7],
        branch,
        remote,
        branch
    )
}
