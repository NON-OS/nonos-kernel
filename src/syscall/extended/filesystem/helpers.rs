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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::RwLock;

pub static PROCESS_CWD: RwLock<BTreeMap<u32, String>> = RwLock::new(BTreeMap::new());

pub fn read_user_string(addr: u64, max_len: usize) -> Result<String, &'static str> {
    if addr == 0 {
        return Err("Null pointer");
    }

    let mut bytes = Vec::with_capacity(256);
    let mut i = 0usize;

    while i < max_len {
        // SAFETY: addr is user-provided pointer to string.
        let byte = unsafe { core::ptr::read((addr + i as u64) as *const u8) };
        if byte == 0 {
            break;
        }
        bytes.push(byte);
        i += 1;
    }

    core::str::from_utf8(&bytes)
        .map(String::from)
        .map_err(|_| "Invalid UTF-8")
}

pub fn normalize_path(path: &str) -> String {
    let mut components: Vec<&str> = Vec::new();

    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            c => components.push(c),
        }
    }

    if components.is_empty() {
        String::from("/")
    } else {
        let mut result = String::new();
        for c in components {
            result.push('/');
            result.push_str(c);
        }
        result
    }
}

pub fn resolve_path_at(dirfd: i32, path: &str) -> String {
    const AT_FDCWD: i32 = -100;

    if path.starts_with('/') {
        return normalize_path(path);
    }

    let base = if dirfd == AT_FDCWD {
        let pid = crate::process::current_pid().unwrap_or(0);
        PROCESS_CWD.read().get(&pid).cloned().unwrap_or_else(|| String::from("/"))
    } else {
        crate::fs::fd::fd_get_path(dirfd).unwrap_or_else(|_| String::from("/"))
    };

    let combined = if base.ends_with('/') {
        alloc::format!("{}{}", base, path)
    } else {
        alloc::format!("{}/{}", base, path)
    };

    normalize_path(&combined)
}
