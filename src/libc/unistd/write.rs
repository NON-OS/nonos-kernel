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

use super::read::Iovec;

#[no_mangle]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    let ret = crate::syscall::sys_write(fd as usize, buf as usize, count);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    ret as isize
}

#[no_mangle]
pub unsafe extern "C" fn pwrite(fd: i32, buf: *const u8, count: usize, offset: i64) -> isize {
    let ret = crate::syscall::sys_pwrite64(fd as usize, buf as usize, count, offset as usize);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    ret as isize
}

#[no_mangle]
pub unsafe extern "C" fn writev(fd: i32, iov: *const Iovec, iovcnt: i32) -> isize {
    let ret = crate::syscall::sys_writev(fd as usize, iov as usize, iovcnt as usize);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    ret as isize
}

#[no_mangle]
pub unsafe extern "C" fn pwritev(fd: i32, iov: *const Iovec, iovcnt: i32, offset: i64) -> isize {
    let ret = crate::syscall::sys_pwritev(fd as usize, iov as usize, iovcnt as usize, offset as usize);
    if ret < 0 {
        crate::libc::errno::set_errno((-ret) as i32);
        return -1;
    }
    ret as isize
}
