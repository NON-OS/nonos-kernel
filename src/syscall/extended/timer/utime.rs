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

use crate::syscall::SyscallResult;
use super::super::errno;
use super::constants::EFAULT;

pub fn handle_utime(filename: u64, times: u64) -> SyscallResult {
    if filename == 0 {
        return errno(EFAULT);
    }

    let path = match crate::syscall::dispatch::util::parse_string_from_user(filename, 4096) {
        Ok(s) => s,
        Err(_) => return errno(EFAULT),
    };

    // SAFETY: times is user-provided pointer to utimbuf struct.
    let times_arr = if times != 0 {
        unsafe {
            let atime = core::ptr::read(times as *const u64);
            let mtime = core::ptr::read((times + 16) as *const u64);
            [atime, mtime]
        }
    } else {
        let now = crate::time::timestamp_millis() / 1000;
        [now, now]
    };

    match crate::fs::set_times(&path, &times_arr) {
        Ok(_) => SyscallResult::success(0),
        Err(_) => errno(2),
    }
}

pub fn handle_utimes(filename: u64, times: u64) -> SyscallResult {
    if filename == 0 {
        return errno(EFAULT);
    }

    let path = match crate::syscall::dispatch::util::parse_string_from_user(filename, 4096) {
        Ok(s) => s,
        Err(_) => return errno(EFAULT),
    };

    // SAFETY: times is user-provided pointer to timeval array.
    let times_arr = if times != 0 {
        unsafe {
            let atime = core::ptr::read(times as *const u64);
            let mtime = core::ptr::read((times + 16) as *const u64);
            [atime, mtime]
        }
    } else {
        let now = crate::time::timestamp_millis() / 1000;
        [now, now]
    };

    match crate::fs::set_times(&path, &times_arr) {
        Ok(_) => SyscallResult::success(0),
        Err(_) => errno(2),
    }
}

pub fn handle_utimensat(dirfd: i32, pathname: u64, times: u64, _flags: i32) -> SyscallResult {
    let path = if pathname != 0 {
        match crate::syscall::dispatch::util::parse_string_from_user(pathname, 4096) {
            Ok(s) => s,
            Err(_) => return errno(EFAULT),
        }
    } else {
        return errno(EFAULT);
    };

    // SAFETY: times is user-provided pointer to timespec array.
    let times_arr = if times != 0 {
        unsafe {
            let atime = core::ptr::read(times as *const u64);
            let mtime = core::ptr::read((times + 16) as *const u64);
            [atime, mtime]
        }
    } else {
        let now = crate::time::timestamp_millis() / 1000;
        [now, now]
    };

    match crate::fs::set_times_at(dirfd, &path, &times_arr) {
        Ok(_) => SyscallResult::success(0),
        Err(_) => errno(2),
    }
}

pub fn handle_futimesat(dirfd: i32, pathname: u64, times: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(EFAULT);
    }

    let path = match crate::syscall::dispatch::util::parse_string_from_user(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(EFAULT),
    };

    // SAFETY: times is user-provided pointer to timeval array.
    let times_arr = if times != 0 {
        unsafe {
            let atime = core::ptr::read(times as *const u64);
            let mtime = core::ptr::read((times + 16) as *const u64);
            [atime, mtime]
        }
    } else {
        let now = crate::time::timestamp_millis() / 1000;
        [now, now]
    };

    match crate::fs::set_times_at(dirfd, &path, &times_arr) {
        Ok(_) => SyscallResult::success(0),
        Err(_) => errno(2),
    }
}
