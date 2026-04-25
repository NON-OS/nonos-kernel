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

use super::super::database::query_installed;
use super::output::{print_line, print_line_fmt};

pub fn cmd_list(args: &[&str]) {
    let mut show_explicit = false;
    let mut show_deps = false;
    let mut show_orphans = false;
    for arg in args {
        match *arg {
            "--explicit" | "-e" => show_explicit = true,
            "--deps" | "-d" => show_deps = true,
            "--orphans" | "-o" => show_orphans = true,
            _ => {}
        }
    }
    if show_orphans {
        let orphans = super::super::database::get_orphans();
        if orphans.is_empty() {
            print_line(b"no orphan packages");
        } else {
            for name in orphans {
                print_line_fmt(name.as_bytes());
            }
        }
        return;
    }
    let packages = query_installed();
    if packages.is_empty() {
        print_line(b"no packages installed");
        return;
    }
    for pkg in packages {
        let reason = match pkg.install_reason {
            super::super::types::InstallReason::Explicit => {
                if show_deps {
                    continue;
                }
                ""
            }
            super::super::types::InstallReason::Dependency
            | super::super::types::InstallReason::Optional => {
                if show_explicit {
                    continue;
                }
                " [dep]"
            }
        };
        print_line_fmt(
            alloc::format!("{} {}{}", pkg.meta.name, pkg.meta.version.to_string(), reason)
                .as_bytes(),
        );
    }
}
