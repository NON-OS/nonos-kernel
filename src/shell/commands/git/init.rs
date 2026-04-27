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
use super::repo;
use alloc::format;
use alloc::string::String;

pub fn cmd_init(args: &[&str], cwd: &str) -> String {
    let path = if args.is_empty() { cwd } else { args[0] };
    if repo::is_repo(path) {
        return format!("Reinitialized existing Git repository in {}", path);
    }
    match repo::init(path) {
        Ok(()) => format!("Initialized empty Git repository in {}/.git/", path),
        Err(e) => format!("error: {}", e),
    }
}
