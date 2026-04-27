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

use alloc::boxed::Box;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysfsEntryType {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct SysfsEntry {
    pub name: String,
    pub entry_type: SysfsEntryType,
    pub inode: u64,
    pub mode: u32,
}

pub type ShowFn = Box<dyn Fn() -> String + Send + Sync>;
pub type StoreFn = Box<dyn Fn(&str) -> Result<(), i32> + Send + Sync>;

pub struct SysfsAttribute {
    pub name: String,
    pub mode: u32,
    pub show: ShowFn,
    pub store: Option<StoreFn>,
}

impl SysfsEntry {
    pub fn file(name: &str, inode: u64, mode: u32) -> Self {
        Self { name: String::from(name), entry_type: SysfsEntryType::File, inode, mode }
    }
    pub fn directory(name: &str, inode: u64) -> Self {
        Self { name: String::from(name), entry_type: SysfsEntryType::Directory, inode, mode: 0o555 }
    }
    pub fn symlink(name: &str, inode: u64) -> Self {
        Self { name: String::from(name), entry_type: SysfsEntryType::Symlink, inode, mode: 0o777 }
    }
}

impl SysfsAttribute {
    pub fn readonly<F>(name: &str, show: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        Self { name: String::from(name), mode: 0o444, show: Box::new(show), store: None }
    }
    pub fn readwrite<F, S>(name: &str, show: F, store: S) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
        S: Fn(&str) -> Result<(), i32> + Send + Sync + 'static,
    {
        Self {
            name: String::from(name),
            mode: 0o644,
            show: Box::new(show),
            store: Some(Box::new(store)),
        }
    }
    pub fn writeonly<S>(name: &str, store: S) -> Self
    where
        S: Fn(&str) -> Result<(), i32> + Send + Sync + 'static,
    {
        Self {
            name: String::from(name),
            mode: 0o200,
            show: Box::new(|| String::new()),
            store: Some(Box::new(store)),
        }
    }
    pub fn is_writable(&self) -> bool {
        self.store.is_some()
    }
}
