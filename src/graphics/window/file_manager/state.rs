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

use core::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use super::constants::{MAX_ENTRIES, MAX_PATH_LEN, MAX_NAME_LEN};
use super::types::{FileEntry, FileSource};

pub(crate) static mut CURRENT_PATH: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];
pub(crate) static CURRENT_PATH_LEN: AtomicU8 = AtomicU8::new(0);

pub(crate) static mut FILE_ENTRIES: [FileEntry; MAX_ENTRIES] = [const { FileEntry {
    name: [0u8; MAX_NAME_LEN],
    name_len: 0,
    is_dir: false,
    size: 0,
    cluster: 0,
} }; MAX_ENTRIES];
pub(crate) static FILE_ENTRY_COUNT: AtomicU8 = AtomicU8::new(0);

pub static FM_SELECTED_ITEM: AtomicU8 = AtomicU8::new(255);

pub(crate) static mut CURRENT_SOURCE: FileSource = FileSource::Ramfs;

pub(crate) static FM_CREATING_FOLDER: AtomicBool = AtomicBool::new(false);
pub(crate) static FM_RENAMING: AtomicBool = AtomicBool::new(false);
pub(crate) static FM_DELETING: AtomicBool = AtomicBool::new(false);

pub(crate) static mut INPUT_BUFFER: [u8; MAX_NAME_LEN] = [0u8; MAX_NAME_LEN];
pub(crate) static INPUT_LEN: AtomicU8 = AtomicU8::new(0);

pub(crate) static mut CLIPBOARD_PATH: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];
pub(crate) static CLIPBOARD_LEN: AtomicU8 = AtomicU8::new(0);
pub(crate) static CLIPBOARD_IS_CUT: AtomicBool = AtomicBool::new(false);
pub(crate) static CLIPBOARD_IS_DIR: AtomicBool = AtomicBool::new(false);

pub static FM_CURRENT_DIR: AtomicU8 = AtomicU8::new(0);

pub(crate) fn get_path() -> &'static str {
    let len = CURRENT_PATH_LEN.load(Ordering::Relaxed) as usize;
    // SAFETY: CURRENT_PATH is valid UTF-8 bytes set by set_path
    // Using addr_of! to avoid static_mut_refs warning
    unsafe {
        let ptr = core::ptr::addr_of!(CURRENT_PATH);
        core::str::from_utf8_unchecked(&(&(*ptr))[..len])
    }
}

pub(crate) fn set_path(path: &str) {
    let bytes = path.as_bytes();
    let len = bytes.len().min(MAX_PATH_LEN - 1);
    // SAFETY: Single-threaded access during file manager operations
    // Using addr_of_mut! to avoid static_mut_refs warning
    unsafe {
        let ptr = core::ptr::addr_of_mut!(CURRENT_PATH);
        (&mut (*ptr))[..len].copy_from_slice(&bytes[..len]);
        for i in len..MAX_PATH_LEN {
            (&mut (*ptr))[i] = 0;
        }
    }
    CURRENT_PATH_LEN.store(len as u8, Ordering::Relaxed);

    if path.starts_with("/disk/") {
        let rest = &path[6..];
        if let Some(slash) = rest.find('/') {
            if let Ok(fs_id) = rest[..slash].parse::<u8>() {
                // SAFETY: Single-threaded access
                // Using addr_of_mut! to avoid static_mut_refs warning
                unsafe {
                    let ptr = core::ptr::addr_of_mut!(CURRENT_SOURCE);
                    *ptr = FileSource::Fat32(fs_id);
                }
            }
        } else if let Ok(fs_id) = rest.parse::<u8>() {
            // SAFETY: Single-threaded access
            unsafe {
                let ptr = core::ptr::addr_of_mut!(CURRENT_SOURCE);
                *ptr = FileSource::Fat32(fs_id);
            }
        }
    } else {
        // SAFETY: Single-threaded access
        unsafe {
            let ptr = core::ptr::addr_of_mut!(CURRENT_SOURCE);
            *ptr = FileSource::Ramfs;
        }
    }
}

pub(crate) fn get_current_source() -> FileSource {
    // SAFETY: Single-threaded access
    // Using addr_of! to avoid static_mut_refs warning
    unsafe {
        let ptr = core::ptr::addr_of!(CURRENT_SOURCE);
        *ptr
    }
}

pub(crate) fn is_input_active() -> bool {
    FM_CREATING_FOLDER.load(Ordering::Relaxed) || FM_RENAMING.load(Ordering::Relaxed)
}

pub(crate) fn get_input_text() -> &'static str {
    let len = INPUT_LEN.load(Ordering::Relaxed) as usize;
    // Using addr_of! to avoid static_mut_refs warning
    unsafe {
        let ptr = core::ptr::addr_of!(INPUT_BUFFER);
        core::str::from_utf8_unchecked(&(&(*ptr))[..len])
    }
}

pub(crate) fn clear_input() {
    INPUT_LEN.store(0, Ordering::Relaxed);
    // Using addr_of_mut! to avoid static_mut_refs warning
    unsafe {
        let ptr = core::ptr::addr_of_mut!(INPUT_BUFFER);
        (&mut (*ptr)).fill(0);
    }
}

pub(crate) fn push_input_char(ch: u8) {
    let len = INPUT_LEN.load(Ordering::Relaxed) as usize;
    if len < MAX_NAME_LEN - 1 {
        // Using addr_of_mut! to avoid static_mut_refs warning
        unsafe {
            let ptr = core::ptr::addr_of_mut!(INPUT_BUFFER);
            (&mut (*ptr))[len] = ch;
        }
        INPUT_LEN.store((len + 1) as u8, Ordering::Relaxed);
    }
}

pub(crate) fn pop_input_char() {
    let len = INPUT_LEN.load(Ordering::Relaxed) as usize;
    if len > 0 {
        // Using addr_of_mut! to avoid static_mut_refs warning
        unsafe {
            let ptr = core::ptr::addr_of_mut!(INPUT_BUFFER);
            (&mut (*ptr))[len - 1] = 0;
        }
        INPUT_LEN.store((len - 1) as u8, Ordering::Relaxed);
    }
}

pub fn is_deleting() -> bool {
    FM_DELETING.load(Ordering::Relaxed)
}
