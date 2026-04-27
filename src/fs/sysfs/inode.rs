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

use super::kobject::get_kobject_entries;
use super::types::{SysfsEntry, SysfsEntryType};
use alloc::string::String;
use alloc::vec::Vec;

pub fn sysfs_lookup(parent_ino: u64, name: &str) -> Option<SysfsEntry> {
    let entries = sysfs_readdir(parent_ino);
    entries.into_iter().find(|e| e.name == name)
}

pub fn sysfs_readdir(inode: u64) -> Vec<SysfsEntry> {
    if inode == 1 {
        return root_entries();
    }
    get_kobject_entries(inode)
}

fn root_entries() -> Vec<SysfsEntry> {
    alloc::vec![
        SysfsEntry::directory("class", 100),
        SysfsEntry::directory("devices", 200),
        SysfsEntry::directory("bus", 300),
        SysfsEntry::directory("kernel", 400),
        SysfsEntry::directory("module", 500),
        SysfsEntry::directory("fs", 600),
        SysfsEntry::directory("firmware", 700),
        SysfsEntry::directory("power", 800),
        SysfsEntry::directory("block", 900),
    ]
}

pub fn sysfs_read_attr(inode: u64) -> Result<String, i32> {
    super::kobject::get_attribute(inode).ok_or(-2)
}

pub fn sysfs_write_attr(inode: u64, data: &str) -> Result<(), i32> {
    super::kobject::store_attribute(inode, data)
}

pub fn sysfs_getattr(inode: u64) -> Result<SysfsAttr, i32> {
    let entry = super::kobject::get_entry(inode).ok_or(-2)?;
    Ok(SysfsAttr {
        ino: inode,
        mode: entry.mode,
        nlink: if entry.entry_type == SysfsEntryType::Directory { 2 } else { 1 },
        size: 4096,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct SysfsAttr {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub size: u64,
}
