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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::types::{Command, SetCommand, SubstituteFlags};

pub fn parse_command(input: &str) -> Command {
    let input = input.trim();

    if input.is_empty() {
        return Command::Unknown(String::new());
    }

    if let Ok(num) = input.parse::<usize>() {
        return Command::Number(num);
    }

    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let cmd = parts[0];
    let args = parts.get(1).map(|s| s.trim());

    match cmd {
        "w" | "write" => Command::Write(args.map(String::from)),
        "q" | "quit" => Command::Quit,
        "wq" | "x" => Command::WriteQuit,
        "q!" | "quit!" => Command::ForceQuit,
        "e" | "edit" => {
            let filename = args.map(String::from).unwrap_or_default();
            Command::Edit(filename)
        }
        "set" => parse_set_command(args.unwrap_or("")),
        "s" | "substitute" => parse_substitute(args.unwrap_or("")),
        "g" | "global" => parse_global(args.unwrap_or("")),
        "d" | "delete" => parse_range_command(args, |start, end| Command::Delete(start, end)),
        "y" | "yank" => parse_range_command(args, |start, end| Command::Yank(start, end)),
        "p" | "put" => Command::Put,
        "reg" | "registers" => Command::Registers,
        "marks" => Command::Marks,
        "h" | "help" => Command::Help,
        "version" => Command::Version,
        _ => Command::Unknown(String::from(input)),
    }
}

fn parse_set_command(args: &str) -> Command {
    let args = args.trim();

    if args.is_empty() || args == "all" {
        return Command::Set(SetCommand::All);
    }

    let (name, value) = if let Some(eq_pos) = args.find('=') {
        let name = &args[..eq_pos];
        let value = &args[eq_pos + 1..];
        (name, Some(value))
    } else if args.starts_with("no") {
        (&args[2..], None)
    } else {
        (args, None)
    };

    let enabled = !args.starts_with("no");

    match name {
        "number" | "nu" => Command::Set(SetCommand::Number(enabled)),
        "relativenumber" | "rnu" => Command::Set(SetCommand::RelativeNumber(enabled)),
        "tabstop" | "ts" => {
            let val = value.and_then(|v| v.parse().ok()).unwrap_or(8);
            Command::Set(SetCommand::TabStop(val))
        }
        "expandtab" | "et" => Command::Set(SetCommand::ExpandTab(enabled)),
        "autoindent" | "ai" => Command::Set(SetCommand::AutoIndent(enabled)),
        "showmatch" | "sm" => Command::Set(SetCommand::ShowMatch(enabled)),
        "ignorecase" | "ic" => Command::Set(SetCommand::IgnoreCase(enabled)),
        "smartcase" | "scs" => Command::Set(SetCommand::SmartCase(enabled)),
        "wrap" => Command::Set(SetCommand::Wrap(enabled)),
        "list" => Command::Set(SetCommand::List),
        _ => Command::Unknown(alloc::format!("set {}", args)),
    }
}

fn parse_substitute(args: &str) -> Command {
    if args.is_empty() {
        return Command::Substitute(String::new(), String::new(), SubstituteFlags::default());
    }

    let delimiter = args.chars().next().unwrap_or('/');

    let parts: Vec<&str> = args[1..].split(delimiter).collect();
    let pattern = parts.first().map(|s| s.to_string()).unwrap_or_default();
    let replacement = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
    let flags_str = parts.get(2).unwrap_or(&"");

    let mut flags = SubstituteFlags::default();
    for c in flags_str.chars() {
        match c {
            'g' => flags.global = true,
            'i' => flags.ignore_case = true,
            'c' => flags.confirm = true,
            _ => {}
        }
    }

    Command::Substitute(pattern, replacement, flags)
}

fn parse_global(args: &str) -> Command {
    if args.is_empty() {
        return Command::Global(String::new(), String::new());
    }

    let delimiter = args.chars().next().unwrap_or('/');
    let parts: Vec<&str> = args[1..].split(delimiter).collect();
    let pattern = parts.first().map(|s| s.to_string()).unwrap_or_default();
    let command = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

    Command::Global(pattern, command)
}

fn parse_range_command<F>(args: Option<&str>, create: F) -> Command
where
    F: FnOnce(Option<usize>, Option<usize>) -> Command,
{
    match args {
        None => create(None, None),
        Some(range) => {
            let parts: Vec<&str> = range.split(',').collect();
            let start = parts.first().and_then(|s| s.trim().parse().ok());
            let end = parts.get(1).and_then(|s| s.trim().parse().ok());
            create(start, end)
        }
    }
}
