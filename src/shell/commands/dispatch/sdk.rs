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

use super::sdk_actions::*;
use crate::graphics::framebuffer::COLOR_WHITE;
use crate::shell::commands::utils::starts_with;
use crate::shell::output::print_line;

pub fn try_dispatch_sdk(cmd: &[u8]) -> bool {
    if cmd == b"sdk" || starts_with(cmd, b"sdk ") {
        let s = core::str::from_utf8(cmd).unwrap_or("");
        let args: alloc::vec::Vec<&str> = s.split_whitespace().skip(1).collect();
        cmd_sdk(&args);
        return true;
    }
    false
}

pub fn cmd_sdk(args: &[&str]) {
    if args.is_empty() {
        print_help();
        return;
    }
    match args[0] {
        "list" => list_installed(),
        "info" => {
            if args.len() > 1 {
                app_info(args[1])
            } else {
                print_line(b"Usage: sdk info <id>", COLOR_WHITE);
            }
        }
        "install" => {
            if args.len() > 1 {
                install_pkg(args[1])
            } else {
                print_line(b"Usage: sdk install <path>", COLOR_WHITE);
            }
        }
        "uninstall" => {
            if args.len() > 1 {
                uninstall_app(args[1])
            } else {
                print_line(b"Usage: sdk uninstall <id>", COLOR_WHITE);
            }
        }
        "run" => {
            if args.len() > 1 {
                run_app(args[1])
            } else {
                print_line(b"Usage: sdk run <id>", COLOR_WHITE);
            }
        }
        _ => print_help(),
    }
}

fn print_help() {
    print_line(b"sdk list              - List installed apps", COLOR_WHITE);
    print_line(b"sdk info <id>         - Show app info", COLOR_WHITE);
    print_line(b"sdk install <path>    - Install from package", COLOR_WHITE);
    print_line(b"sdk uninstall <id>    - Uninstall app", COLOR_WHITE);
    print_line(b"sdk run <id>          - Run app", COLOR_WHITE);
}
