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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcEntryType {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct ProcEntry {
    pub name: String,
    pub entry_type: ProcEntryType,
    pub inode: u64,
    pub mode: u32,
}

#[derive(Debug, Clone)]
pub struct ProcInode {
    pub ino: u64,
    pub entry_type: ProcEntryType,
    pub pid: Option<i32>,
    pub subpath: String,
}

impl ProcEntry {
    pub fn file(name: &str, inode: u64) -> Self {
        Self { name: String::from(name), entry_type: ProcEntryType::File, inode, mode: 0o444 }
    }

    pub fn directory(name: &str, inode: u64) -> Self {
        Self { name: String::from(name), entry_type: ProcEntryType::Directory, inode, mode: 0o555 }
    }

    pub fn symlink(name: &str, inode: u64) -> Self {
        Self { name: String::from(name), entry_type: ProcEntryType::Symlink, inode, mode: 0o777 }
    }
}

impl ProcInode {
    pub fn root() -> Self {
        Self { ino: 1, entry_type: ProcEntryType::Directory, pid: None, subpath: String::new() }
    }

    pub fn new_file(ino: u64, subpath: &str) -> Self {
        Self { ino, entry_type: ProcEntryType::File, pid: None, subpath: String::from(subpath) }
    }

    pub fn new_dir(ino: u64, subpath: &str) -> Self {
        Self {
            ino,
            entry_type: ProcEntryType::Directory,
            pid: None,
            subpath: String::from(subpath),
        }
    }

    pub fn for_pid(ino: u64, pid: i32) -> Self {
        Self { ino, entry_type: ProcEntryType::Directory, pid: Some(pid), subpath: String::new() }
    }
}

pub fn generate_inode(base: u64, pid: Option<i32>, offset: u64) -> u64 {
    match pid {
        Some(p) => (p as u64) << 20 | offset,
        None => base + offset,
    }
}
