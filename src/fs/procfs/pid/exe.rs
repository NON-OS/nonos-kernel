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

pub fn read_pid_exe(pid: i32) -> Result<String, i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    if proc.exe_path.is_empty() {
        return Err(-2);
    }
    Ok(proc.exe_path.clone())
}

pub fn get_exe_deleted(pid: i32) -> Result<bool, i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    Ok(proc.exe_deleted)
}

pub fn get_exe_inode(pid: i32) -> Result<u64, i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    Ok(proc.exe_inode)
}

pub fn get_exe_dev(pid: i32) -> Result<(u32, u32), i32> {
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    Ok((proc.exe_dev_major, proc.exe_dev_minor))
}

pub fn format_exe_link(pid: i32) -> Result<String, i32> {
    let path = read_pid_exe(pid)?;
    let deleted = get_exe_deleted(pid)?;
    if deleted {
        Ok(alloc::format!("{} (deleted)", path))
    } else {
        Ok(path)
    }
}
