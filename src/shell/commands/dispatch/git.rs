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

use crate::display::framebuffer::COLOR_WHITE;
use crate::shell::commands::files::get_cwd;
use crate::shell::commands::git;
use crate::shell::output::print_line;

pub fn try_dispatch_git(cmd: &[u8]) -> bool {
    let s = core::str::from_utf8(cmd).unwrap_or("");
    if !s.starts_with("git ") && s != "git" {
        return false;
    }
    let parts: alloc::vec::Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        print_output(&git::cmd_git_help());
        return true;
    }
    let cwd = get_cwd();
    let args: alloc::vec::Vec<&str> = parts[2..].to_vec();
    let out = match parts[1] {
        "init" => git::cmd_init(&args, cwd),
        "clone" => git::cmd_clone(&args, cwd),
        "status" => git::cmd_status(&args, cwd),
        "add" => git::cmd_add(&args, cwd),
        "commit" => git::cmd_commit(&args, cwd),
        "push" => git::cmd_push(&args, cwd),
        "pull" => git::cmd_pull(&args, cwd),
        "log" => git::cmd_log(&args, cwd),
        "diff" => git::cmd_diff(&args, cwd),
        "branch" => git::cmd_branch(&args, cwd),
        "checkout" => git::cmd_checkout(&args, cwd),
        "remote" => git::cmd_remote(&args, cwd),
        "help" | "--help" | "-h" => git::cmd_git_help(),
        _ => alloc::format!("git: '{}' is not a git command. See 'git help'.", parts[1]),
    };
    print_output(&out);
    true
}

fn print_output(s: &str) {
    for line in s.lines() {
        print_line(line.as_bytes(), COLOR_WHITE);
    }
}
