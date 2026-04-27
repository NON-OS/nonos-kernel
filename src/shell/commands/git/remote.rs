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
use super::{config, repo};
use alloc::format;
use alloc::string::String;

pub fn cmd_remote(args: &[&str], cwd: &str) -> String {
    if !repo::is_repo(cwd) {
        return String::from("fatal: not a git repository");
    }
    if args.is_empty() {
        let entries = config::read_config(cwd);
        let mut out = String::new();
        for (k, _) in entries {
            if k.starts_with("remote.") && k.ends_with(".url") {
                let name = &k[7..k.len() - 4];
                out.push_str(name);
                out.push('\n');
            }
        }
        return if out.is_empty() { String::from("No remotes configured") } else { out };
    }
    match args[0] {
        "add" if args.len() >= 3 => {
            if config::set_remote_url(cwd, args[1], args[2]).is_ok() {
                format!("Added remote '{}'", args[1])
            } else {
                String::from("error: failed to add remote")
            }
        }
        "remove" | "rm" if args.len() >= 2 => {
            format!("Removed remote '{}'", args[1])
        }
        "-v" => {
            let entries = config::read_config(cwd);
            let mut out = String::new();
            for (k, v) in entries {
                if k.starts_with("remote.") && k.ends_with(".url") {
                    let name = &k[7..k.len() - 4];
                    out.push_str(&format!("{}\t{} (fetch)\n{}\t{} (push)\n", name, v, name, v));
                }
            }
            if out.is_empty() {
                String::from("No remotes configured")
            } else {
                out
            }
        }
        _ => String::from("usage: git remote [add <name> <url> | remove <name> | -v]"),
    }
}
