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

use core::sync::atomic::Ordering;
use super::constants::MAX_PATH_LEN;
use super::state::{get_path, set_path, FILE_ENTRIES, FM_SELECTED_ITEM, FILE_ENTRY_COUNT};
use super::listing::refresh_listing;

pub fn init() {
    set_path("/ram");
    refresh_listing();
}

pub fn go_up() {
    let path = get_path();
    if path == "/ram" || path == "/disk" {
        return;
    }

    if let Some(pos) = path.rfind('/') {
        if pos == 0 {
            set_path("/");
        } else {
            set_path(&path[..pos]);
        }
        refresh_listing();
    }
}

pub fn open_selected() {
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 {
        return;
    }

    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize;
    if selected as usize >= count {
        return;
    }

    // SAFETY: Single-threaded file manager access
    let entry = unsafe { &FILE_ENTRIES[selected as usize] };
    if entry.is_dir {
        let name_len = entry.name_len as usize;
        if let Ok(name) = core::str::from_utf8(&entry.name[..name_len]) {
            go_into(name);
        }
    }
}

pub fn go_into(name: &str) {
    let path = get_path();
    let mut new_path = [0u8; MAX_PATH_LEN];
    let path_bytes = path.as_bytes();
    let name_bytes = name.as_bytes();

    let mut pos = path_bytes.len();
    new_path[..pos].copy_from_slice(path_bytes);

    if pos > 0 && path_bytes[pos - 1] != b'/' {
        new_path[pos] = b'/';
        pos += 1;
    }

    let name_len = name_bytes.len().min(MAX_PATH_LEN - pos - 1);
    new_path[pos..pos + name_len].copy_from_slice(&name_bytes[..name_len]);
    pos += name_len;

    if let Ok(s) = core::str::from_utf8(&new_path[..pos]) {
        set_path(s);
        refresh_listing();
    }
}
