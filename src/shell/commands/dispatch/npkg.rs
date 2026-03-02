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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_WHITE, COLOR_RED};
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_npkg(cmd: &[u8]) -> bool {
    if cmd == b"npkg" || starts_with(cmd, b"npkg ") {
        cmd_npkg(cmd);
        true
    } else {
        false
    }
}

fn cmd_npkg(cmd: &[u8]) {
    let args_str = if cmd.len() > 5 {
        core::str::from_utf8(&cmd[5..]).unwrap_or("")
    } else {
        ""
    };

    let args: alloc::vec::Vec<&str> = args_str.split_whitespace().collect();

    if args.is_empty() {
        print_line(b"NONOS Package Manager (npkg)", COLOR_WHITE);
        print_line(b"", COLOR_WHITE);
        print_line(b"Commands:", COLOR_WHITE);
        print_line(b"  npkg install <pkg>   Install packages", COLOR_WHITE);
        print_line(b"  npkg remove <pkg>    Remove packages", COLOR_WHITE);
        print_line(b"  npkg upgrade         Upgrade all packages", COLOR_WHITE);
        print_line(b"  npkg search <query>  Search packages", COLOR_WHITE);
        print_line(b"  npkg info <pkg>      Show package info", COLOR_WHITE);
        print_line(b"  npkg list            List installed packages", COLOR_WHITE);
        print_line(b"  npkg sync            Sync repositories", COLOR_WHITE);
        print_line(b"  npkg clean           Clean package cache", COLOR_WHITE);
        print_line(b"  npkg verify          Verify database integrity", COLOR_WHITE);
        print_line(b"  npkg files <pkg>     List package files", COLOR_WHITE);
        print_line(b"  npkg owner <file>    Find file owner", COLOR_WHITE);
        return;
    }

    let subcmd = args[0];
    let subargs: alloc::vec::Vec<&str> = args.iter().skip(1).cloned().collect();

    match subcmd {
        "install" | "i" => crate::npkg::commands::cmd_install(&subargs),
        "remove" | "r" | "uninstall" => crate::npkg::commands::cmd_remove(&subargs),
        "upgrade" | "u" | "update" => crate::npkg::commands::cmd_upgrade(&subargs),
        "search" | "s" | "find" => crate::npkg::commands::cmd_search(&subargs),
        "info" | "show" => crate::npkg::commands::cmd_info(&subargs),
        "list" | "l" | "ls" => crate::npkg::commands::cmd_list(&subargs),
        "sync" | "refresh" => crate::npkg::commands::cmd_sync(&subargs),
        "clean" | "clear" => crate::npkg::commands::cmd_clean(&subargs),
        "verify" | "check" => crate::npkg::commands::cmd_verify(&subargs),
        "files" | "f" => crate::npkg::commands::cmd_files(&subargs),
        "owner" | "o" => crate::npkg::commands::cmd_owner(&subargs),
        _ => {
            print_line(b"Unknown npkg command. Type 'npkg' for help.", COLOR_RED);
        }
    }
}
