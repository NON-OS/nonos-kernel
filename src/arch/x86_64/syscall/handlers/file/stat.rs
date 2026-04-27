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

use crate::usercopy::{copy_to_user, validate_user_write};

const STAT_SIZE: usize = 144;
const EFAULT: i64 = -14;

pub fn syscall_stat(pathname: u64, statbuf: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if pathname == 0 || statbuf == 0 {
        return EFAULT as u64;
    }
    if validate_user_write(statbuf, STAT_SIZE).is_err() {
        return EFAULT as u64;
    }
    let zeroed_stat = [0u8; STAT_SIZE];
    if copy_to_user(statbuf, &zeroed_stat).is_err() {
        return EFAULT as u64;
    }
    0
}

pub fn syscall_fstat(fd: u64, statbuf: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if statbuf == 0 {
        return EFAULT as u64;
    }
    if validate_user_write(statbuf, STAT_SIZE).is_err() {
        return EFAULT as u64;
    }
    let mut kernel_stat = [0u8; STAT_SIZE];
    match crate::fs::fd::fd_fstat(fd as i32, kernel_stat.as_mut_ptr()) {
        Ok(()) => {
            if copy_to_user(statbuf, &kernel_stat).is_err() {
                return EFAULT as u64;
            }
            0
        }
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_lstat(pathname: u64, statbuf: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    syscall_stat(pathname, statbuf, 0, 0, 0, 0)
}
