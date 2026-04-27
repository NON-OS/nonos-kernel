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
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let argv = proc.argv.lock();
    if argv.is_empty() {
        return Err(-2);
    }
    Ok(argv[0].clone())
}

pub fn get_exe_deleted(pid: i32) -> Result<bool, i32> {
    let path = read_pid_exe(pid)?;
    Ok(!crate::fs::ramfs::NONOS_FILESYSTEM.exists(&path))
}

pub fn get_exe_inode(pid: i32) -> Result<u64, i32> {
    let path = read_pid_exe(pid)?;
    crate::fs::ramfs::NONOS_FILESYSTEM.get_file_info(&path).map(|info| info.inode).map_err(|_| -2)
}

pub fn get_exe_dev(pid: i32) -> Result<(u32, u32), i32> {
    let _ = crate::process::get_process(pid as u32).ok_or(-3)?;
    Ok((0, 1))
}

pub fn format_exe_link(pid: i32) -> Result<String, i32> {
    let path = read_pid_exe(pid)?;
    if get_exe_deleted(pid)? {
        Ok(alloc::format!("{} (deleted)", path))
    } else {
        Ok(path)
    }
}
