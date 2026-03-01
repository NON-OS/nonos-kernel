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

use crate::syscall::{handle_syscall, SyscallNumber};

#[inline]
pub fn sys_open(path_ptr: u64, flags: u64, mode: u64) -> i64 {
    handle_syscall(SyscallNumber::Open as u64, path_ptr, flags, mode, 0, 0, 0) as i64
}

#[inline]
pub fn sys_read(fd: u64, buf: u64, len: u64) -> i64 {
    handle_syscall(SyscallNumber::Read as u64, fd, buf, len, 0, 0, 0) as i64
}

#[inline]
pub fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    handle_syscall(SyscallNumber::Write as u64, fd, buf, len, 0, 0, 0) as i64
}

#[inline]
pub fn sys_close(fd: u64) -> i64 {
    handle_syscall(SyscallNumber::Close as u64, fd, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_stat(path_ptr: u64, statbuf: u64) -> i64 {
    handle_syscall(SyscallNumber::Stat as u64, path_ptr, statbuf, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_fstat(fd: u64, statbuf: u64) -> i64 {
    handle_syscall(SyscallNumber::Fstat as u64, fd, statbuf, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_lseek(fd: u64, offset: u64, whence: u64) -> i64 {
    handle_syscall(SyscallNumber::Lseek as u64, fd, offset, whence, 0, 0, 0) as i64
}

#[inline]
pub fn sys_mkdir(path_ptr: u64, mode: u64) -> i64 {
    handle_syscall(SyscallNumber::Mkdir as u64, path_ptr, mode, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rmdir(path_ptr: u64) -> i64 {
    handle_syscall(SyscallNumber::Rmdir as u64, path_ptr, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_unlink(path_ptr: u64) -> i64 {
    handle_syscall(SyscallNumber::Unlink as u64, path_ptr, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rename(old_ptr: u64, new_ptr: u64) -> i64 {
    handle_syscall(SyscallNumber::Rename as u64, old_ptr, new_ptr, 0, 0, 0, 0) as i64
}
