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

use core::sync::atomic::{AtomicUsize, Ordering};

const MAX_PATH: usize = 256;
const MAX_FILENAME: usize = 64;

static mut CURRENT_PATH: [u8; MAX_PATH] = [0u8; MAX_PATH];
static PATH_LEN: AtomicUsize = AtomicUsize::new(0);
static mut FILENAME: [u8; MAX_FILENAME] = [0u8; MAX_FILENAME];
static FILENAME_LEN: AtomicUsize = AtomicUsize::new(0);

pub(super) fn set_path(path: &[u8]) {
    let len = path.len().min(MAX_PATH);
    unsafe {
        for i in 0..len {
            CURRENT_PATH[i] = path[i];
        }
    }
    PATH_LEN.store(len, Ordering::Relaxed);
}

pub(super) fn get_path() -> &'static [u8] {
    let len = PATH_LEN.load(Ordering::Relaxed);
    unsafe { &CURRENT_PATH[..len] }
}

pub(super) fn navigate_to(name: &[u8]) {
    let current_len = PATH_LEN.load(Ordering::Relaxed);
    if name == b".." {
        navigate_up();
        return;
    }
    unsafe {
        let new_len = (current_len + 1 + name.len()).min(MAX_PATH);
        if current_len > 0 && CURRENT_PATH[current_len - 1] != b'/' {
            CURRENT_PATH[current_len] = b'/';
            for i in 0..name.len() {
                if current_len + 1 + i < MAX_PATH {
                    CURRENT_PATH[current_len + 1 + i] = name[i];
                }
            }
            PATH_LEN.store(new_len, Ordering::Relaxed);
        }
    }
}

fn navigate_up() {
    let len = PATH_LEN.load(Ordering::Relaxed);
    if len <= 1 {
        return;
    }
    unsafe {
        let mut i = len - 1;
        while i > 0 && CURRENT_PATH[i] != b'/' {
            i -= 1;
        }
        if i == 0 {
            i = 1;
        }
        PATH_LEN.store(i, Ordering::Relaxed);
    }
}

pub(super) fn set_filename(name: &[u8]) {
    let len = name.len().min(MAX_FILENAME);
    unsafe {
        for i in 0..len {
            FILENAME[i] = name[i];
        }
    }
    FILENAME_LEN.store(len, Ordering::Relaxed);
}

pub(super) fn get_filename() -> &'static [u8] {
    let len = FILENAME_LEN.load(Ordering::Relaxed);
    unsafe { &FILENAME[..len] }
}

pub(super) fn push_filename_char(c: u8) {
    let len = FILENAME_LEN.load(Ordering::Relaxed);
    if len < MAX_FILENAME - 1 {
        unsafe { FILENAME[len] = c; }
        FILENAME_LEN.store(len + 1, Ordering::Relaxed);
    }
}

pub(super) fn pop_filename_char() {
    let len = FILENAME_LEN.load(Ordering::Relaxed);
    if len > 0 {
        FILENAME_LEN.store(len - 1, Ordering::Relaxed);
    }
}
