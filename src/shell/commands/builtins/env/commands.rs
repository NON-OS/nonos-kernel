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

use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_YELLOW};
use crate::shell::commands::utils::trim_bytes;
use crate::shell::output::print_line;

use super::types::get_env;

pub fn cmd_export(cmd: &[u8]) {
    let args = if cmd.len() > 7 {
        trim_bytes(&cmd[7..])
    } else {
        get_env().list_exported();
        return;
    };

    if args.is_empty() {
        get_env().list_exported();
        return;
    }

    if let Some(eq_pos) = args.iter().position(|&c| c == b'=') {
        let name = &args[..eq_pos];
        let value = if eq_pos + 1 < args.len() {
            &args[eq_pos + 1..]
        } else {
            b"" as &[u8]
        };

        if name.is_empty() {
            print_line(b"export: invalid variable name", COLOR_RED);
            return;
        }

        let value = if value.starts_with(b"\"") && value.ends_with(b"\"") && value.len() > 1 {
            &value[1..value.len() - 1]
        } else if value.starts_with(b"'") && value.ends_with(b"'") && value.len() > 1 {
            &value[1..value.len() - 1]
        } else {
            value
        };

        if get_env().set(name, value, true) {
            let mut line = [0u8; 64];
            line[..10].copy_from_slice(b"Exported: ");
            let name_len = name.len().min(32);
            line[10..10 + name_len].copy_from_slice(&name[..name_len]);
            print_line(&line[..10 + name_len], COLOR_GREEN);
        } else {
            print_line(b"export: environment full", COLOR_RED);
        }
    } else if let Some(value) = get_env().get(args) {
        let mut line = [0u8; 64];
        let name_len = args.len().min(24);
        line[..name_len].copy_from_slice(&args[..name_len]);
        line[name_len] = b'=';
        let val_len = value.len().min(32);
        line[name_len + 1..name_len + 1 + val_len].copy_from_slice(&value[..val_len]);
        print_line(&line[..name_len + 1 + val_len], COLOR_TEXT);
    } else {
        print_line(b"export: variable not set", COLOR_YELLOW);
    }
}

pub fn cmd_unset(cmd: &[u8]) {
    let name = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: unset <variable>", COLOR_TEXT_DIM);
        return;
    };

    if name.is_empty() {
        print_line(b"unset: variable name required", COLOR_RED);
        return;
    }

    let protected: &[&[u8]] = &[
        b"USER", b"HOME", b"SHELL", b"PATH", b"ANON_MODE", b"ZEROSTATE",
    ];

    for &p in protected {
        if p == name {
            print_line(b"unset: cannot unset protected variable", COLOR_RED);
            return;
        }
    }

    if get_env().unset(name) {
        let mut line = [0u8; 48];
        line[..8].copy_from_slice(b"Unset: ");
        let name_len = name.len().min(32);
        line[8..8 + name_len].copy_from_slice(&name[..name_len]);
        print_line(&line[..8 + name_len], COLOR_GREEN);
    } else {
        print_line(b"unset: variable not found", COLOR_YELLOW);
    }
}

pub fn cmd_printenv(cmd: &[u8]) {
    let name = if cmd.len() > 9 {
        trim_bytes(&cmd[9..])
    } else {
        get_env().list_all();
        return;
    };

    if name.is_empty() {
        get_env().list_all();
        return;
    }

    if let Some(value) = get_env().get(name) {
        print_line(value, COLOR_TEXT);
    }
}
