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
use spin::Mutex;

pub const XATTR_CREATE: i32 = 1;
pub const XATTR_REPLACE: i32 = 2;
pub const XATTR_SIZE_MAX: usize = 65536;
pub const XATTR_LIST_MAX: usize = 65536;
pub const XATTR_NAME_MAX: usize = 255;

static XATTR_STORE: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>> =
    Mutex::new(BTreeMap::new());

pub struct XattrStorage;

impl XattrStorage {
    pub fn set(path: &str, name: &str, value: &[u8], flags: i32) -> Result<(), i32> {
        if name.len() > XATTR_NAME_MAX || value.len() > XATTR_SIZE_MAX {
            return Err(34);
        }
        let mut store = XATTR_STORE.lock();
        let attrs = store.entry(String::from(path)).or_insert_with(BTreeMap::new);
        let exists = attrs.contains_key(name);
        if flags == XATTR_CREATE && exists {
            return Err(17);
        }
        if flags == XATTR_REPLACE && !exists {
            return Err(61);
        }
        attrs.insert(String::from(name), value.to_vec());
        Ok(())
    }

    pub fn get(path: &str, name: &str) -> Result<Vec<u8>, i32> {
        let store = XATTR_STORE.lock();
        store.get(path).and_then(|attrs| attrs.get(name)).cloned().ok_or(61)
    }

    pub fn list(path: &str) -> Result<Vec<String>, i32> {
        let store = XATTR_STORE.lock();
        Ok(store.get(path).map(|attrs| attrs.keys().cloned().collect()).unwrap_or_default())
    }

    pub fn remove(path: &str, name: &str) -> Result<(), i32> {
        let mut store = XATTR_STORE.lock();
        if let Some(attrs) = store.get_mut(path) {
            if attrs.remove(name).is_some() {
                return Ok(());
            }
        }
        Err(61)
    }

    pub fn get_by_fd(fd: i32, name: &str) -> Result<Vec<u8>, i32> {
        let path = crate::fs::fd::fd_get_path(fd).map_err(|_| 9)?;
        Self::get(&path, name)
    }

    pub fn set_by_fd(fd: i32, name: &str, value: &[u8], flags: i32) -> Result<(), i32> {
        let path = crate::fs::fd::fd_get_path(fd).map_err(|_| 9)?;
        Self::set(&path, name, value, flags)
    }

    pub fn list_by_fd(fd: i32) -> Result<Vec<String>, i32> {
        let path = crate::fs::fd::fd_get_path(fd).map_err(|_| 9)?;
        Self::list(&path)
    }

    pub fn remove_by_fd(fd: i32, name: &str) -> Result<(), i32> {
        let path = crate::fs::fd::fd_get_path(fd).map_err(|_| 9)?;
        Self::remove(&path, name)
    }
}
