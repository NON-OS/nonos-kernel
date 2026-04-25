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

use super::super::errno;
use super::constants::EFAULT;
use crate::syscall::SyscallResult;
use crate::usercopy::read_user_value;

pub fn handle_utime(filename: u64, times: u64) -> SyscallResult {
    if filename == 0 {
        return errno(EFAULT);
    }

    let path = match crate::syscall::dispatch::util::parse_string_from_user(filename, 4096) {
        Ok(s) => s,
        Err(_) => return errno(EFAULT),
    };

    let times_arr = if times != 0 {
        let atime: u64 = match read_user_value(times) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        let mtime: u64 = match read_user_value(times + 16) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        [atime, mtime]
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

    let times_arr = if times != 0 {
        let atime: u64 = match read_user_value(times) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        let mtime: u64 = match read_user_value(times + 16) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        [atime, mtime]
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

    let times_arr = if times != 0 {
        let atime: u64 = match read_user_value(times) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        let mtime: u64 = match read_user_value(times + 16) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        [atime, mtime]
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

    let times_arr = if times != 0 {
        let atime: u64 = match read_user_value(times) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        let mtime: u64 = match read_user_value(times + 16) {
            Ok(v) => v,
            Err(_) => return errno(EFAULT),
        };
        [atime, mtime]
    } else {
        let now = crate::time::timestamp_millis() / 1000;
        [now, now]
    };

    match crate::fs::set_times_at(dirfd, &path, &times_arr) {
        Ok(_) => SyscallResult::success(0),
        Err(_) => errno(2),
    }
}
