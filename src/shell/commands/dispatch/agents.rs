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

use super::agents_actions::*;
use crate::graphics::framebuffer::COLOR_WHITE;
use crate::shell::commands::utils::starts_with;
use crate::shell::output::print_line;

pub fn try_dispatch_agents(cmd: &[u8]) -> bool {
    if cmd == b"agent" || starts_with(cmd, b"agent ") {
        let s = core::str::from_utf8(cmd).unwrap_or("");
        let args: alloc::vec::Vec<&str> = s.split_whitespace().skip(1).collect();
        cmd_agent(&args);
        return true;
    }
    false
}

fn join_args(args: &[&str]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(a);
    }
    s
}

pub fn cmd_agent(args: &[&str]) {
    if args.is_empty() {
        print_help();
        return;
    }
    match args[0] {
        "list" => list_agents(),
        "create" => {
            if args.len() > 1 {
                create_agent(args[1])
            } else {
                print_line(b"Usage: agent create <name>", COLOR_WHITE);
            }
        }
        "preset" => {
            if args.len() > 1 {
                create_preset(args[1])
            } else {
                list_presets();
            }
        }
        "run" => {
            if args.len() > 2 {
                run_agent(args[1], &join_args(&args[2..]))
            } else {
                print_line(b"Usage: agent run <id> <prompt>", COLOR_WHITE);
            }
        }
        "delete" => {
            if args.len() > 1 {
                delete_agent(args[1])
            } else {
                print_line(b"Usage: agent delete <id>", COLOR_WHITE);
            }
        }
        _ => print_help(),
    }
}

fn print_help() {
    print_line(b"agent list              - List all agents", COLOR_WHITE);
    print_line(b"agent create <name>     - Create new agent", COLOR_WHITE);
    print_line(b"agent preset [name]     - Create from preset", COLOR_WHITE);
    print_line(b"agent run <id> <prompt> - Run agent", COLOR_WHITE);
    print_line(b"agent delete <id>       - Delete agent", COLOR_WHITE);
}
