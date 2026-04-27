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

use crate::fs::procfs::types::ProcEntry;
use alloc::string::String;
use alloc::vec::Vec;

pub fn list_pid_fds(pid: i32) -> Result<Vec<ProcEntry>, i32> {
    let _proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let fds = crate::fs::get_process_fds(pid)?;
    let base = (pid as u64) << 20 | 0x10000;
    let mut entries = Vec::new();
    for (fd_num, _) in fds.iter().enumerate() {
        entries.push(ProcEntry::symlink(&alloc::format!("{}", fd_num), base | fd_num as u64));
    }
    Ok(entries)
}

pub fn read_pid_fd(pid: i32, fd: i32) -> Result<String, i32> {
    let _proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let file = crate::fs::get_process_fd(pid, fd).ok_or(-9)?;
    Ok(file.path.clone())
}

pub fn read_pid_fdinfo(pid: i32, fd: i32) -> Result<String, i32> {
    let file = crate::fs::get_process_fd(pid, fd).ok_or(-9)?;
    Ok(alloc::format!(
        "pos:\t{}\nflags:\t{:o}\nmnt_id:\t{}\nino:\t{}\n",
        file.position,
        file.flags,
        file.mount_id,
        file.inode
    ))
}

pub fn get_fd_count(pid: i32) -> Result<usize, i32> {
    let fds = crate::fs::get_process_fds(pid)?;
    Ok(fds.len())
}

pub fn get_fd_limit(pid: i32) -> Result<(u64, u64), i32> {
    let _proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    Ok((1024, 1048576))
}

#[derive(Debug, Clone)]
pub struct FdInfo {
    pub fd: i32,
    pub path: String,
    pub flags: u32,
    pub position: u64,
    pub mount_id: u32,
    pub inode: u64,
}
