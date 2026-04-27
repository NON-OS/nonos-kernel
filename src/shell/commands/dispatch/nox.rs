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

use crate::graphics::framebuffer::{COLOR_GRAY, COLOR_GREEN, COLOR_RED, COLOR_WHITE};
use crate::shell::commands::utils::starts_with;
use crate::shell::output::print_line;

pub fn try_dispatch_nox(cmd: &[u8]) -> bool {
    if cmd == b"nox" || starts_with(cmd, b"nox ") {
        cmd_nox(cmd);
        true
    } else {
        false
    }
}

fn cmd_nox(cmd: &[u8]) {
    let args_str = if cmd.len() > 4 { core::str::from_utf8(&cmd[4..]).unwrap_or("") } else { "" };
    let args: alloc::vec::Vec<&str> = args_str.split_whitespace().collect();

    if args.is_empty() {
        print_nox_help();
        return;
    }

    let subcmd = args[0];
    let subargs: alloc::vec::Vec<&str> = args.iter().skip(1).cloned().collect();

    match subcmd {
        "install" | "i" | "add" => nox_install(&subargs),
        "remove" | "rm" | "uninstall" => nox_remove(&subargs),
        "upgrade" | "up" | "update" => nox_upgrade(&subargs),
        "search" | "s" | "find" => nox_search(&subargs),
        "info" | "show" => nox_info(&subargs),
        "list" | "ls" => nox_list(&subargs),
        "tap" => nox_tap(&subargs),
        "untap" => nox_untap(&subargs),
        "taps" => nox_taps(),
        "doctor" | "dr" => nox_doctor(),
        "outdated" => nox_outdated(),
        "deps" => nox_deps(&subargs),
        "leaves" => nox_leaves(),
        "clean" | "cleanup" => nox_clean(&subargs),
        "pin" => nox_pin(&subargs),
        "unpin" => nox_unpin(&subargs),
        "config" => nox_config(&subargs),
        "version" | "-v" | "--version" => nox_version(),
        "help" | "-h" | "--help" => print_nox_help(),
        _ => print_line(b"Unknown nox command. Type 'nox help'", COLOR_RED),
    }
}

fn print_nox_help() {
    print_line(b"\x1b[1mnox\x1b[0m - NONOS Package Manager", COLOR_WHITE);
    print_line(b"", COLOR_WHITE);
    print_line(b"\x1b[1mUsage:\x1b[0m nox <command> [options]", COLOR_WHITE);
    print_line(b"", COLOR_WHITE);
    print_line(b"\x1b[1mCommands:\x1b[0m", COLOR_GRAY);
    print_line(b"  install <formula>   Install a formula", COLOR_WHITE);
    print_line(b"  remove <formula>    Remove a formula", COLOR_WHITE);
    print_line(b"  upgrade [formula]   Upgrade formulas", COLOR_WHITE);
    print_line(b"  search <text>       Search formulas", COLOR_WHITE);
    print_line(b"  info <formula>      Show formula info", COLOR_WHITE);
    print_line(b"  list                List installed formulas", COLOR_WHITE);
    print_line(b"  outdated            List outdated formulas", COLOR_WHITE);
    print_line(b"  deps <formula>      Show dependencies", COLOR_WHITE);
    print_line(b"  leaves              List formulas not required by others", COLOR_WHITE);
    print_line(b"  tap <user/repo>     Add a formula repository", COLOR_WHITE);
    print_line(b"  untap <user/repo>   Remove a formula repository", COLOR_WHITE);
    print_line(b"  taps                List tapped repositories", COLOR_WHITE);
    print_line(b"  doctor              Check system for issues", COLOR_WHITE);
    print_line(b"  clean               Remove old versions and cache", COLOR_WHITE);
    print_line(b"  pin <formula>       Prevent formula from upgrading", COLOR_WHITE);
    print_line(b"  unpin <formula>     Allow formula to upgrade", COLOR_WHITE);
}

fn nox_install(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox install <formula> [formula...]", COLOR_WHITE);
        return;
    }
    let opts = crate::nox::commands::install::InstallOptions::default();
    match crate::nox::commands::cmd_install(args, &opts) {
        Ok(_) => print_line(b"Installation complete", COLOR_GREEN),
        Err(e) => {
            let msg = alloc::format!("Error: {}", e);
            print_line(msg.as_bytes(), COLOR_RED);
        }
    }
}

fn nox_remove(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox remove <formula> [formula...]", COLOR_WHITE);
        return;
    }
    let opts = crate::nox::commands::remove::RemoveOptions::default();
    match crate::nox::commands::cmd_remove(args, &opts) {
        Ok(_) => print_line(b"Removal complete", COLOR_GREEN),
        Err(e) => {
            let msg = alloc::format!("Error: {}", e);
            print_line(msg.as_bytes(), COLOR_RED);
        }
    }
}

fn nox_upgrade(args: &[&str]) {
    if args.is_empty() {
        let _ = crate::nox::commands::cmd_upgrade_all();
    } else {
        let _ = crate::nox::commands::cmd_upgrade(args);
    }
}

fn nox_search(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox search <text>", COLOR_WHITE);
        return;
    }
    let _ = crate::nox::commands::cmd_search(args[0]);
}

fn nox_info(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox info <formula>", COLOR_WHITE);
        return;
    }
    let _ = crate::nox::commands::cmd_info(args[0]);
}

fn nox_list(_args: &[&str]) {
    let _ = crate::nox::commands::cmd_list();
}

fn nox_tap(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox tap <user/repo>", COLOR_WHITE);
        return;
    }
    let url = if args.len() > 1 { Some(args[1]) } else { None };
    let _ = crate::nox::commands::cmd_tap(args[0], url);
}

fn nox_untap(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox untap <user/repo>", COLOR_WHITE);
        return;
    }
    let _ = crate::nox::commands::cmd_untap(args[0]);
}

fn nox_taps() {
    let _ = crate::nox::commands::cmd_taps();
}

fn nox_doctor() {
    let _ = crate::nox::commands::cmd_doctor();
}

fn nox_outdated() {
    let _ = crate::nox::commands::cmd_outdated();
}

fn nox_deps(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox deps <formula>", COLOR_WHITE);
        return;
    }
    let tree = args.iter().any(|a| *a == "--tree" || *a == "-t");
    let _ = crate::nox::commands::cmd_deps(args[0], tree);
}

fn nox_leaves() {
    let _ = crate::nox::commands::cmd_leaves();
}

fn nox_clean(args: &[&str]) {
    let prune_all = args.iter().any(|a| *a == "--prune" || *a == "-s");
    let _ = crate::nox::commands::cmd_clean(prune_all);
}

fn nox_pin(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox pin <formula>", COLOR_WHITE);
        return;
    }
    let _ = crate::nox::commands::cmd_pin(args[0]);
}

fn nox_unpin(args: &[&str]) {
    if args.is_empty() {
        print_line(b"Usage: nox unpin <formula>", COLOR_WHITE);
        return;
    }
    let _ = crate::nox::commands::cmd_unpin(args[0]);
}

fn nox_config(_args: &[&str]) {
    print_line(b"NOX_PREFIX: /nox", COLOR_WHITE);
    print_line(b"NOX_CELLAR: /nox/Cellar", COLOR_WHITE);
    print_line(b"NOX_CACHE:  /nox/Cache", COLOR_WHITE);
    print_line(b"NOX_TAPS:   /nox/Library/Taps", COLOR_WHITE);
}

fn nox_version() {
    print_line(alloc::format!("nox {}", crate::nox::NOX_VERSION).as_bytes(), COLOR_WHITE);
}
