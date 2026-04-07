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

pub fn read_pid_cwd(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let root_dir = proc.root_dir.lock();
    if root_dir.is_empty() {
        return Ok(String::from("/"));
    }
    Ok(root_dir.clone())
}

pub fn get_cwd_inode(pid: i32) -> Result<u64, i32> {
    let _proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    Ok(2)
}

pub fn get_cwd_dev(pid: i32) -> Result<(u32, u32), i32> {
    let _proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    Ok((0, 1))
}

pub fn set_pid_cwd(pid: i32, path: &str) -> Result<(), i32> {
    crate::process::set_cwd(pid as u32, path)
}
