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

use super::state::*;
use crate::fs::ramfs;
use core::sync::atomic::Ordering;

pub(crate) fn create_folder(name: &str) -> bool {
    if name.is_empty() || name.len() >= NAME_LEN {
        return false;
    }
    init_path();
    let cur_len = CURRENT_PATH_LEN.load(Ordering::SeqCst) as usize;
    let name_len = name.len().min(NAME_LEN - 1);
    let mut path = [0u8; MAX_PATH];
    unsafe {
        path[..cur_len].copy_from_slice(&CURRENT_PATH[..cur_len]);
    }
    path[cur_len] = b'/';
    path[cur_len + 1..cur_len + 1 + name_len].copy_from_slice(name.as_bytes());
    if let Ok(path_str) = core::str::from_utf8(&path[..cur_len + 1 + name_len]) {
        if ramfs::create_dir(path_str).is_ok() {
            refresh();
            return true;
        }
    }
    false
}

pub(crate) fn create_file(name: &str) -> bool {
    if name.is_empty() || name.len() >= NAME_LEN {
        return false;
    }
    init_path();
    let cur_len = CURRENT_PATH_LEN.load(Ordering::SeqCst) as usize;
    let name_len = name.len().min(NAME_LEN - 1);
    let mut path = [0u8; MAX_PATH];
    unsafe {
        path[..cur_len].copy_from_slice(&CURRENT_PATH[..cur_len]);
    }
    path[cur_len] = b'/';
    path[cur_len + 1..cur_len + 1 + name_len].copy_from_slice(name.as_bytes());
    if let Ok(path_str) = core::str::from_utf8(&path[..cur_len + 1 + name_len]) {
        if ramfs::create_file(path_str, b"").is_ok() {
            refresh();
            return true;
        }
    }
    false
}

pub(crate) fn delete_selected() -> bool {
    let sel = SELECTED_ICON.load(Ordering::SeqCst);
    if sel == 255 || sel as usize >= ICON_COUNT.load(Ordering::SeqCst) as usize {
        return false;
    }
    init_path();
    let icon = unsafe { &ICONS[sel as usize] };
    let cur_len = CURRENT_PATH_LEN.load(Ordering::SeqCst) as usize;
    let name_len = icon.name_len as usize;
    let mut path = [0u8; MAX_PATH];
    unsafe {
        path[..cur_len].copy_from_slice(&CURRENT_PATH[..cur_len]);
    }
    path[cur_len] = b'/';
    path[cur_len + 1..cur_len + 1 + name_len].copy_from_slice(&icon.name[..name_len]);
    if let Ok(path_str) = core::str::from_utf8(&path[..cur_len + 1 + name_len]) {
        if ramfs::delete(path_str).is_ok() {
            SELECTED_ICON.store(255, Ordering::SeqCst);
            refresh();
            return true;
        }
    }
    false
}

pub(crate) fn has_selection() -> bool {
    let sel = SELECTED_ICON.load(Ordering::SeqCst);
    sel != 255 && (sel as usize) < ICON_COUNT.load(Ordering::SeqCst) as usize
}

pub(crate) fn clear_selection() {
    SELECTED_ICON.store(255, Ordering::SeqCst);
}
