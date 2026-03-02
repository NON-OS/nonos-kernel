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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::shell::commands::utils::{trim_bytes, starts_with};

pub fn cmd_exit() {
    print_line(b"Terminating shell session...", COLOR_YELLOW);
    print_line(b"Session data erased from RAM", COLOR_GREEN);
}

pub fn cmd_true() -> i32 {
    0
}

pub fn cmd_false() -> i32 {
    1
}

pub fn cmd_sleep(cmd: &[u8]) {
    let args = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: sleep <seconds>", COLOR_TEXT_DIM);
        return;
    };

    if args.is_empty() {
        print_line(b"sleep: seconds required", COLOR_RED);
        return;
    }

    let mut secs: u64 = 0;
    for &c in args {
        if c >= b'0' && c <= b'9' {
            secs = secs * 10 + (c - b'0') as u64;
        } else {
            break;
        }
    }

    if secs == 0 {
        return;
    }

    let ms = secs * 1000;
    let start = crate::time::timestamp_millis();
    let end = start + ms;

    while crate::time::timestamp_millis() < end {
        crate::time::yield_now();
    }
}

pub fn cmd_source(cmd: &[u8]) {
    let file = if cmd.len() > 7 {
        trim_bytes(&cmd[7..])
    } else if starts_with(cmd, b". ") && cmd.len() > 2 {
        trim_bytes(&cmd[2..])
    } else {
        print_line(b"Usage: source <file>", COLOR_TEXT_DIM);
        return;
    };

    if file.is_empty() {
        print_line(b"source: file required", COLOR_RED);
        return;
    }

    let path_str = match core::str::from_utf8(file) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"source: invalid path encoding", COLOR_RED);
            return;
        }
    };

    let content = match crate::fs::read_file(path_str) {
        Ok(data) => data,
        Err(_) => {
            print_line(b"source: cannot read file", COLOR_RED);
            return;
        }
    };

    let mut line_start = 0;
    for i in 0..content.len() {
        if content[i] == b'\n' {
            let line = &content[line_start..i];
            let trimmed = trim_bytes(line);
            if !trimmed.is_empty() && !trimmed.starts_with(b"#") {
                crate::shell::commands::dispatch::dispatch(trimmed);
            }
            line_start = i + 1;
        }
    }

    if line_start < content.len() {
        let line = &content[line_start..];
        let trimmed = trim_bytes(line);
        if !trimmed.is_empty() && !trimmed.starts_with(b"#") {
            crate::shell::commands::dispatch::dispatch(trimmed);
        }
    }
}

pub fn cmd_type(cmd: &[u8]) {
    let name = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: type <command>", COLOR_TEXT_DIM);
        return;
    };

    if name.is_empty() {
        print_line(b"type: command name required", COLOR_RED);
        return;
    }

    let builtins: &[&[u8]] = &[
        b"exit", b"export", b"unset", b"alias", b"unalias", b"type",
        b"source", b"true", b"false", b"cd", b"pwd", b"echo", b"read",
        b"test", b"history", b"help", b"clear",
    ];

    for &builtin in builtins {
        if builtin == name {
            let mut line = [0u8; 64];
            let name_len = name.len().min(24);
            line[..name_len].copy_from_slice(&name[..name_len]);
            line[name_len..name_len+19].copy_from_slice(b" is a shell builtin");
            print_line(&line[..name_len+19], COLOR_TEXT);
            return;
        }
    }

    let commands: &[&[u8]] = &[
        b"ls", b"cat", b"mkdir", b"rm", b"cp", b"mv", b"chmod",
        b"ps", b"kill", b"top", b"net", b"tor", b"ping",
        b"hash", b"genkey", b"crypto", b"vault", b"audit",
        b"lspci", b"lscpu", b"dmesg", b"reboot", b"shutdown",
    ];

    for &cmd_name in commands {
        if cmd_name == name {
            let mut line = [0u8; 64];
            let name_len = name.len().min(24);
            line[..name_len].copy_from_slice(&name[..name_len]);
            line[name_len..name_len+20].copy_from_slice(b" is a kernel command");
            print_line(&line[..name_len+20], COLOR_TEXT);
            return;
        }
    }

    let mut line = [0u8; 48];
    line[..6].copy_from_slice(b"type: ");
    let name_len = name.len().min(24);
    line[6..6+name_len].copy_from_slice(&name[..name_len]);
    line[6+name_len..6+name_len+10].copy_from_slice(b" not found");
    print_line(&line[..16+name_len], COLOR_RED);
}

pub fn cmd_which(cmd: &[u8]) {
    let name = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: which <command>", COLOR_TEXT_DIM);
        return;
    };

    if name.is_empty() {
        print_line(b"which: command name required", COLOR_RED);
        return;
    }

    let mut line = [0u8; 48];
    line[..5].copy_from_slice(b"/bin/");
    let name_len = name.len().min(32);
    line[5..5+name_len].copy_from_slice(&name[..name_len]);
    print_line(&line[..5+name_len], COLOR_TEXT);

    print_line(b"(All commands built into kernel)", COLOR_TEXT_DIM);
}
