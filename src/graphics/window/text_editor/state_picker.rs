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

use core::sync::atomic::Ordering;

use super::state::{
    PATH_SIZE, MAX_PICKER_FILES, MAX_PICKER_NAME,
    PICKER_ACTIVE, PICKER_SELECTED, PICKER_COUNT,
    PICKER_FILES, PICKER_LENS, PICKER_IS_DIR, PICKER_PATH, PICKER_PATH_LEN,
};

pub(crate) fn picker_open(path: &str) {
    let path_bytes = path.as_bytes();
    let path_len = path_bytes.len().min(PATH_SIZE - 1);
    unsafe {
        for i in 0..path_len {
            PICKER_PATH[i] = path_bytes[i];
        }
        for i in path_len..PATH_SIZE {
            PICKER_PATH[i] = 0;
        }
    }
    PICKER_PATH_LEN.store(path_len, Ordering::Relaxed);

    picker_refresh();

    PICKER_SELECTED.store(0, Ordering::Relaxed);
    PICKER_ACTIVE.store(true, Ordering::Relaxed);
}

pub(crate) fn picker_refresh() {
    use crate::fs::ramfs;

    let path_len = PICKER_PATH_LEN.load(Ordering::Relaxed);
    let path = unsafe {
        core::str::from_utf8_unchecked(&PICKER_PATH[..path_len])
    };

    unsafe {
        for i in 0..MAX_PICKER_FILES {
            PICKER_LENS[i] = 0;
            PICKER_IS_DIR[i] = false;
        }
    }

    let mut count = 0usize;

    if path != "/ram" && path != "/" {
        unsafe {
            PICKER_FILES[count][0] = b'.';
            PICKER_FILES[count][1] = b'.';
            PICKER_LENS[count] = 2;
            PICKER_IS_DIR[count] = true;
        }
        count += 1;
    }

    if let Ok(entries) = ramfs::list_dir_entries(path) {
        for entry in entries.iter().take(MAX_PICKER_FILES - count) {
            let name_bytes = entry.name.as_bytes();
            let name_len = name_bytes.len().min(MAX_PICKER_NAME - 1);

            unsafe {
                for i in 0..name_len {
                    PICKER_FILES[count][i] = name_bytes[i];
                }
                PICKER_LENS[count] = name_len;
                PICKER_IS_DIR[count] = entry.is_dir;
            }
            count += 1;
        }
    }

    PICKER_COUNT.store(count, Ordering::Relaxed);
}

pub(crate) fn picker_close() {
    PICKER_ACTIVE.store(false, Ordering::Relaxed);
}

pub(crate) fn picker_is_active() -> bool {
    PICKER_ACTIVE.load(Ordering::Relaxed)
}

pub(crate) fn picker_select(index: usize) {
    let count = PICKER_COUNT.load(Ordering::Relaxed);
    if index < count {
        PICKER_SELECTED.store(index, Ordering::Relaxed);
    }
}

pub(crate) fn picker_get_selected_path() -> Option<alloc::string::String> {
    use alloc::string::String;

    let selected = PICKER_SELECTED.load(Ordering::Relaxed);
    let count = PICKER_COUNT.load(Ordering::Relaxed);

    if selected >= count {
        return None;
    }

    let name_len = unsafe { PICKER_LENS[selected] };
    if name_len == 0 {
        return None;
    }

    let name = unsafe {
        core::str::from_utf8_unchecked(&PICKER_FILES[selected][..name_len])
    };

    if name == ".." {
        let path_len = PICKER_PATH_LEN.load(Ordering::Relaxed);
        let current_path = unsafe {
            core::str::from_utf8_unchecked(&PICKER_PATH[..path_len])
        };

        if let Some(pos) = current_path.rfind('/') {
            if pos == 0 {
                return Some(String::from("/ram"));
            }
            return Some(String::from(&current_path[..pos]));
        }
        return Some(String::from("/ram"));
    }

    let path_len = PICKER_PATH_LEN.load(Ordering::Relaxed);
    let mut full_path = String::new();

    unsafe {
        if let Ok(base) = core::str::from_utf8(&PICKER_PATH[..path_len]) {
            full_path.push_str(base);
        }
    }

    if !full_path.ends_with('/') {
        full_path.push('/');
    }
    full_path.push_str(name);

    Some(full_path)
}

pub(crate) fn picker_is_selected_dir() -> bool {
    let selected = PICKER_SELECTED.load(Ordering::Relaxed);
    unsafe { PICKER_IS_DIR[selected] }
}

pub(crate) fn picker_navigate_into() {
    if let Some(path) = picker_get_selected_path() {
        picker_open(&path);
    }
}
