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

pub fn read_pid_root(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    if proc.root.is_empty() {
        return Ok(String::from("/"));
    }
    Ok(proc.root.clone())
}

pub fn get_root_inode(pid: i32) -> Result<u64, i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    Ok(proc.root_inode)
}

pub fn get_root_dev(pid: i32) -> Result<(u32, u32), i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    Ok((proc.root_dev_major, proc.root_dev_minor))
}

pub fn set_pid_root(pid: i32, path: &str) -> Result<(), i32> {
    crate::process::set_root(pid, path)
}

pub fn is_chrooted(pid: i32) -> Result<bool, i32> {
    let root = read_pid_root(pid)?;
    Ok(root != "/")
}
