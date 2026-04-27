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

use super::super::installer::{upgrade_all, upgrade_packages, UpgradeOptions};
use super::output::{print_line, print_line_fmt};
use alloc::vec::Vec;

pub fn cmd_upgrade(args: &[&str]) {
    let mut options = UpgradeOptions::default();
    let mut packages = Vec::new();
    for arg in args {
        match *arg {
            "--no-deps" => options.no_deps = true,
            "--no-scripts" => options.no_scripts = true,
            "--download-only" | "-d" => options.download_only = true,
            _ if !arg.starts_with('-') => packages.push(*arg),
            _ => {
                print_line_fmt(alloc::format!("unknown option: {}", arg).as_bytes());
                return;
            }
        }
    }
    if packages.is_empty() {
        print_line(b"upgrading all packages...");
        match upgrade_all(&options) {
            Ok(count) => {
                if count == 0 {
                    print_line(b"all packages up to date");
                } else {
                    print_line_fmt(alloc::format!("upgraded {} packages", count).as_bytes());
                }
            }
            Err(e) => print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes()),
        }
    } else {
        match upgrade_packages(&packages, &options) {
            Ok(()) => print_line(b"upgrade complete"),
            Err(e) => print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes()),
        }
    }
}
