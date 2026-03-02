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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED};
use crate::shell::commands::utils::{trim_bytes, starts_with};

pub fn cmd_test(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: test <expression>", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Operators:", COLOR_TEXT_WHITE);
        print_line(b"  -n STRING    True if length > 0", COLOR_TEXT_DIM);
        print_line(b"  -z STRING    True if length = 0", COLOR_TEXT_DIM);
        print_line(b"  -e FILE      True if file exists", COLOR_TEXT_DIM);
        print_line(b"  -d FILE      True if directory", COLOR_TEXT_DIM);
        print_line(b"  S1 = S2      True if strings equal", COLOR_TEXT_DIM);
        print_line(b"  N1 -eq N2    True if numbers equal", COLOR_TEXT_DIM);
        return;
    };

    if starts_with(args, b"-n ") {
        let s = trim_bytes(&args[3..]);
        if !s.is_empty() {
            print_line(b"true (0)", COLOR_GREEN);
        } else {
            print_line(b"false (1)", COLOR_RED);
        }
    } else if starts_with(args, b"-z ") {
        let s = trim_bytes(&args[3..]);
        if s.is_empty() {
            print_line(b"true (0)", COLOR_GREEN);
        } else {
            print_line(b"false (1)", COLOR_RED);
        }
    } else if starts_with(args, b"-e ") {
        let path = trim_bytes(&args[3..]);
        let path_str = core::str::from_utf8(path).unwrap_or("");
        if crate::fs::ramfs::exists(path_str) {
            print_line(b"true (0)", COLOR_GREEN);
        } else {
            print_line(b"false (1)", COLOR_RED);
        }
    } else if starts_with(args, b"-d ") {
        let path = trim_bytes(&args[3..]);
        let path_str = core::str::from_utf8(path).unwrap_or("");
        if crate::fs::is_directory(path_str) {
            print_line(b"true (0)", COLOR_GREEN);
        } else {
            print_line(b"false (1)", COLOR_RED);
        }
    } else if starts_with(args, b"-f ") {
        let path = trim_bytes(&args[3..]);
        let path_str = core::str::from_utf8(path).unwrap_or("");
        if crate::fs::ramfs::exists(path_str) && !crate::fs::is_directory(path_str) {
            print_line(b"true (0)", COLOR_GREEN);
        } else {
            print_line(b"false (1)", COLOR_RED);
        }
    } else {
        print_line(b"test: expression evaluation limited", COLOR_YELLOW);
    }
}

pub fn cmd_read(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: read [-r] <variable>", COLOR_TEXT_DIM);
        return;
    };

    let (raw_mode, var_name) = if starts_with(args, b"-r ") {
        (true, trim_bytes(&args[3..]))
    } else {
        (false, args)
    };

    if var_name.is_empty() {
        print_line(b"read: variable name required", COLOR_RED);
        return;
    }

    if !crate::shell::commands::pipeline::has_stdin() {
        print_line(b"read: no input (use with pipe)", COLOR_YELLOW);
        return;
    }

    let lines = crate::shell::commands::pipeline::get_stdin_lines();
    if lines.is_empty() {
        crate::shell::commands::builtins::env::get_env().set(var_name, b"", false);
        return;
    }

    let first_line = &lines[0];
    let value = if raw_mode {
        first_line.clone()
    } else {
        let mut processed = alloc::vec::Vec::new();
        let mut escape = false;
        for &b in first_line.iter() {
            if escape {
                processed.push(b);
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else {
                processed.push(b);
            }
        }
        processed
    };

    crate::shell::commands::builtins::env::get_env().set(var_name, &value, false);

    let mut msg = [0u8; 64];
    msg[..6].copy_from_slice(b"Read: ");
    let name_len = var_name.len().min(24);
    msg[6..6+name_len].copy_from_slice(&var_name[..name_len]);
    msg[6+name_len] = b'=';
    let val_len = value.len().min(24);
    msg[7+name_len..7+name_len+val_len].copy_from_slice(&value[..val_len]);
    print_line(&msg[..7+name_len+val_len], COLOR_GREEN);
}

pub fn cmd_eval(cmd: &[u8]) {
    let expr = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: eval <expression>", COLOR_TEXT_DIM);
        return;
    };

    if expr.is_empty() {
        return;
    }

    let expanded = crate::shell::commands::expand::expand_variables(expr);
    crate::shell::commands::dispatch::dispatch(&expanded);
}

pub fn cmd_exec(cmd: &[u8]) {
    let prog = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: exec <command>", COLOR_TEXT_DIM);
        return;
    };

    if prog.is_empty() {
        return;
    }

    crate::shell::commands::dispatch::dispatch(prog);
}
