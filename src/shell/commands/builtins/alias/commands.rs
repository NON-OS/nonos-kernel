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

use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT_DIM, COLOR_YELLOW};
use crate::shell::commands::utils::trim_bytes;
use crate::shell::output::print_line;

use super::types::get_aliases;

pub fn cmd_alias(cmd: &[u8]) {
    let args = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        get_aliases().list();
        return;
    };

    if args.is_empty() {
        get_aliases().list();
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
            print_line(b"alias: invalid alias name", COLOR_RED);
            return;
        }

        let value = if value.starts_with(b"'") && value.ends_with(b"'") && value.len() > 1 {
            &value[1..value.len() - 1]
        } else if value.starts_with(b"\"") && value.ends_with(b"\"") && value.len() > 1 {
            &value[1..value.len() - 1]
        } else {
            value
        };

        if get_aliases().set(name, value) {
            let mut line = [0u8; 48];
            line[..14].copy_from_slice(b"Alias set: ");
            let name_len = name.len().min(24);
            line[14..14 + name_len].copy_from_slice(&name[..name_len]);
            print_line(&line[..14 + name_len], COLOR_GREEN);
        } else {
            print_line(b"alias: alias table full", COLOR_RED);
        }
    } else if let Some(value) = get_aliases().get(args) {
        let mut line = [0u8; 160];

        line[..6].copy_from_slice(b"alias ");
        let mut pos = 6;

        let name_len = args.len().min(16);
        line[pos..pos + name_len].copy_from_slice(&args[..name_len]);
        pos += name_len;

        line[pos..pos + 2].copy_from_slice(b"='");
        pos += 2;

        let val_len = value.len().min(80);
        line[pos..pos + val_len].copy_from_slice(&value[..val_len]);
        pos += val_len;

        line[pos] = b'\'';
        pos += 1;

        print_line(&line[..pos], COLOR_GREEN);
    } else {
        let mut line = [0u8; 48];
        line[..7].copy_from_slice(b"alias: ");
        let name_len = args.len().min(24);
        line[7..7 + name_len].copy_from_slice(&args[..name_len]);
        line[7 + name_len..7 + name_len + 10].copy_from_slice(b" not found");
        print_line(&line[..17 + name_len], COLOR_YELLOW);
    }
}

pub fn cmd_unalias(cmd: &[u8]) {
    let name = if cmd.len() > 8 {
        trim_bytes(&cmd[8..])
    } else {
        print_line(b"Usage: unalias <name>", COLOR_TEXT_DIM);
        return;
    };

    if name.is_empty() {
        print_line(b"unalias: alias name required", COLOR_RED);
        return;
    }

    if name == b"-a" {
        get_aliases().secure_erase();
        print_line(b"All aliases removed", COLOR_GREEN);
        return;
    }

    if get_aliases().unset(name) {
        let mut line = [0u8; 48];
        line[..16].copy_from_slice(b"Alias removed: ");
        let name_len = name.len().min(24);
        line[16..16 + name_len].copy_from_slice(&name[..name_len]);
        print_line(&line[..16 + name_len], COLOR_GREEN);
    } else {
        print_line(b"unalias: alias not found", COLOR_YELLOW);
    }
}
