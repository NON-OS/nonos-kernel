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

use super::pid::pid_entries;
use super::root::procfs_root_entries;
use super::types::{ProcEntry, ProcEntryType, ProcInode};
use alloc::string::String;
use alloc::vec::Vec;

pub fn procfs_lookup(parent: &ProcInode, name: &str) -> Option<ProcInode> {
    if parent.ino == 1 {
        return lookup_root(name);
    }
    if let Some(pid) = parent.pid {
        return lookup_pid_entry(pid, name);
    }
    None
}

fn lookup_root(name: &str) -> Option<ProcInode> {
    if name == "self" {
        return Some(ProcInode {
            ino: 2,
            entry_type: ProcEntryType::Symlink,
            pid: None,
            subpath: String::from("self"),
        });
    }
    if let Ok(pid) = name.parse::<i32>() {
        return Some(ProcInode::for_pid(pid as u64 * 1000 + 100, pid));
    }
    let entries = procfs_root_entries();
    entries.iter().find(|e| e.name == name).map(|e| ProcInode::new_file(e.inode, &e.name))
}

fn lookup_pid_entry(pid: i32, name: &str) -> Option<ProcInode> {
    let entries = pid_entries(pid);
    entries.iter().find(|e| e.name == name).map(|e| {
        let mut inode = ProcInode::new_file(e.inode, &e.name);
        inode.pid = Some(pid);
        inode.entry_type = e.entry_type;
        inode
    })
}

pub fn procfs_readdir(inode: &ProcInode) -> Vec<ProcEntry> {
    if inode.ino == 1 {
        let mut entries = procfs_root_entries();
        entries.insert(0, ProcEntry::symlink("self", 2));
        for pid in get_active_pids() {
            entries.push(ProcEntry::directory(&alloc::format!("{}", pid), pid as u64 * 1000 + 100));
        }
        return entries;
    }
    if let Some(pid) = inode.pid {
        return pid_entries(pid);
    }
    Vec::new()
}

fn get_active_pids() -> Vec<i32> {
    crate::process::list_all_pids().iter().map(|&p| p as i32).collect()
}
