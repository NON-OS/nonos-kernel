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

use super::operations::{create_file, create_folder, rename_selected};
use super::state::{
    clear_input, get_input_text, is_input_active, pop_input_char, push_input_char,
    FM_CREATING_FILE, FM_CREATING_FOLDER, FM_RENAMING,
};
use core::sync::atomic::Ordering;

pub fn handle_key(ch: u8) -> bool {
    if !is_input_active() {
        return false;
    }
    if ch >= 0x20 && ch < 0x7F {
        push_input_char(ch);
        return true;
    }
    false
}

pub fn handle_special_key(key: u8) -> bool {
    if !is_input_active() {
        return false;
    }

    match key {
        0x0E => {
            pop_input_char();
            true
        }
        0x1C => {
            commit_operation();
            true
        }
        0x01 => {
            cancel();
            true
        }
        _ => false,
    }
}

fn commit_operation() {
    let name = get_input_text();
    if FM_RENAMING.load(Ordering::Relaxed) {
        let _ = rename_selected(name);
        FM_RENAMING.store(false, Ordering::Relaxed);
    } else if FM_CREATING_FOLDER.load(Ordering::Relaxed) {
        if !name.is_empty() {
            let _ = create_folder(name);
        }
        FM_CREATING_FOLDER.store(false, Ordering::Relaxed);
    } else if FM_CREATING_FILE.load(Ordering::Relaxed) {
        if !name.is_empty() {
            let _ = create_file(name);
        }
        FM_CREATING_FILE.store(false, Ordering::Relaxed);
    }
    clear_input();
}

pub fn cancel() {
    FM_RENAMING.store(false, Ordering::Relaxed);
    FM_CREATING_FOLDER.store(false, Ordering::Relaxed);
    FM_CREATING_FILE.store(false, Ordering::Relaxed);
    clear_input();
}
