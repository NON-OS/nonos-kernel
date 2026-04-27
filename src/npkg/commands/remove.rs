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

use super::super::installer::{remove_packages, RemoveOptions};
use super::output::{print_line, print_line_fmt};
use alloc::vec::Vec;

pub fn cmd_remove(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg remove <package> [packages...]");
        return;
    }
    let mut options = RemoveOptions::default();
    let mut packages = Vec::new();
    for arg in args {
        match *arg {
            "--recursive" | "-r" => options.recursive = true,
            "--no-scripts" => options.no_scripts = true,
            "--no-config" => options.keep_config = false,
            "--purge" => options.purge = true,
            _ if !arg.starts_with('-') => packages.push(*arg),
            _ => {
                print_line_fmt(alloc::format!("unknown option: {}", arg).as_bytes());
                return;
            }
        }
    }
    if packages.is_empty() {
        print_line(b"no packages specified");
        return;
    }
    match remove_packages(&packages, &options) {
        Ok(()) => print_line(b"removal complete"),
        Err(e) => print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes()),
    }
}
