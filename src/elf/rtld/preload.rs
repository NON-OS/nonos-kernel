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
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;

pub type PreloadList = Vec<String>;

static PRELOAD_LIST: Mutex<PreloadList> = Mutex::new(Vec::new());

pub fn parse_preload(envp: *const *const u8) {
    unsafe {
        let mut i = 0;
        while !ptr::read(envp.add(i)).is_null() {
            let env = ptr::read(envp.add(i));
            if starts_with(env, b"LD_PRELOAD=") {
                let val = env.add(11);
                parse_preload_value(val);
            } else if starts_with(env, b"LD_LIBRARY_PATH=") {
                let val = env.add(16);
                parse_library_path(val);
            } else if starts_with(env, b"LD_BIND_NOW=") {
                super::init::set_bind_now(true);
            } else if starts_with(env, b"LD_AUDIT=") {
                let val = env.add(9);
                parse_audit_value(val);
            }
            i += 1;
        }
    }
}

unsafe fn starts_with(s: *const u8, prefix: &[u8]) -> bool {
    for (i, &b) in prefix.iter().enumerate() {
        if ptr::read(s.add(i)) != b {
            return false;
        }
    }
    true
}

unsafe fn parse_preload_value(val: *const u8) {
    let len = strlen(val);
    let s = core::str::from_utf8_unchecked(core::slice::from_raw_parts(val, len));
    for lib in s.split(':') {
        if lib.is_empty() {
            continue;
        }
        for part in lib.split(' ') {
            if !part.is_empty() {
                PRELOAD_LIST.lock().push(String::from(part));
            }
        }
    }
}

unsafe fn parse_library_path(val: *const u8) {
    let len = strlen(val);
    let s = core::str::from_utf8_unchecked(core::slice::from_raw_parts(val, len));
    super::search::add_search_paths_from_env(s);
}

unsafe fn parse_audit_value(val: *const u8) {
    let len = strlen(val);
    let s = core::str::from_utf8_unchecked(core::slice::from_raw_parts(val, len));
    super::audit::parse_ld_audit(s);
}

unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while ptr::read(s.add(len)) != 0 {
        len += 1;
    }
    len
}

pub fn load_preloaded() {
    let list = PRELOAD_LIST.lock().clone();
    for lib in &list {
        let _ = super::load::load_library(lib);
    }
}

pub fn get_preload_list() -> PreloadList {
    PRELOAD_LIST.lock().clone()
}

pub fn add_preload(lib: &str) {
    PRELOAD_LIST.lock().push(String::from(lib));
}

pub fn clear_preload() {
    PRELOAD_LIST.lock().clear();
}
