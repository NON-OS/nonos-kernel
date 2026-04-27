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
use spin::Mutex;

pub type LibrarySearchPath = Vec<String>;

static SEARCH_PATHS: Mutex<LibrarySearchPath> = Mutex::new(Vec::new());

static DEFAULT_PATHS: &[&str] = &["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"];

pub fn init_search_paths() {
    let mut paths = SEARCH_PATHS.lock();
    if paths.is_empty() {
        for p in DEFAULT_PATHS {
            paths.push(String::from(*p));
        }
    }
}

pub fn add_search_path(path: &str) {
    let mut paths = SEARCH_PATHS.lock();
    if !paths.iter().any(|p| p == path) {
        paths.insert(0, String::from(path));
    }
}

pub fn add_search_paths_from_env(env_val: &str) {
    for path in env_val.split(':') {
        if !path.is_empty() {
            add_search_path(path);
        }
    }
}

pub fn get_search_paths() -> Vec<String> {
    SEARCH_PATHS.lock().clone()
}

pub fn search_library(name: &str) -> Result<String, i32> {
    if name.contains('/') {
        if file_exists(name) {
            return Ok(String::from(name));
        }
        return Err(-2);
    }
    let paths = SEARCH_PATHS.lock().clone();
    for dir in &paths {
        let mut full_path = dir.clone();
        full_path.push('/');
        full_path.push_str(name);
        if file_exists(&full_path) {
            return Ok(full_path);
        }
    }
    Err(-2)
}

fn file_exists(path: &str) -> bool {
    let mut buf = [0u8; 256];
    let path_bytes = path.as_bytes();
    if path_bytes.len() >= 255 {
        return false;
    }
    buf[..path_bytes.len()].copy_from_slice(path_bytes);
    buf[path_bytes.len()] = 0;
    crate::syscall::core::sys_access(buf.as_ptr() as usize, 0) == 0
}

pub fn add_rpath(rpath: &str) {
    for path in rpath.split(':') {
        if !path.is_empty() {
            add_search_path(path);
        }
    }
}

pub fn add_runpath(runpath: &str) {
    for path in runpath.split(':') {
        if !path.is_empty() {
            add_search_path(path);
        }
    }
}

pub fn clear_search_paths() {
    SEARCH_PATHS.lock().clear();
}

pub fn reset_to_default_paths() {
    let mut paths = SEARCH_PATHS.lock();
    paths.clear();
    for p in DEFAULT_PATHS {
        paths.push(String::from(*p));
    }
}
