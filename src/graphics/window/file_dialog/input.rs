// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::entries::{get_entry, refresh_entries};
use super::path::{get_path, navigate_to, pop_filename_char, push_filename_char};
use super::render::{get_selected, select_next, select_prev};
use super::state::{close_dialog, get_mode, is_open, set_result, DialogMode, DialogResult};

pub fn handle_key(key: u8, _ctrl: bool) -> bool {
    if !is_open() {
        return false;
    }
    match key {
        0x1B => {
            close_dialog();
            set_result(DialogResult::Cancelled);
            true
        }
        0x26 => {
            select_prev();
            true
        }
        0x28 => {
            select_next();
            true
        }
        0x0D => {
            handle_enter();
            true
        }
        0x08 | 0x7F => {
            if get_mode() == DialogMode::Save {
                pop_filename_char();
            }
            true
        }
        c if c >= 0x20 && c < 0x7F => {
            if get_mode() == DialogMode::Save {
                push_filename_char(c);
            }
            true
        }
        _ => false,
    }
}

fn handle_enter() {
    let selected = get_selected();
    if let Some(entry) = get_entry(selected) {
        if entry.is_dir {
            navigate_to(&entry.name[..entry.name_len]);
            refresh_entries(get_path());
        } else {
            set_result(DialogResult::Selected);
            close_dialog();
        }
    }
}

pub fn handle_click(_mx: i32, _my: i32) -> bool {
    if !is_open() {
        return false;
    }
    true
}
