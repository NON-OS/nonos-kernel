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

use crate::usercopy::{validate_user_read, validate_user_write, copy_to_user, copy_from_user};

const EFAULT: i64 = -14;
const EBADF: i64 = -9;

pub fn syscall_lseek(fd: u64, offset: u64, whence: u64, _: u64, _: u64, _: u64) -> u64 {
    match crate::fs::nonos_vfs::vfs_lseek(fd as u32, offset as i64, whence as u32) {
        Ok(pos) => pos as u64,
        Err(_) => EBADF as u64,
    }
}

pub fn syscall_pread64(fd: u64, buf: u64, count: u64, offset: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return EFAULT as u64;
    }
    if validate_user_write(buf, count as usize).is_err() {
        return EFAULT as u64;
    }

    let mut kernel_buf = alloc::vec![0u8; count as usize];
    match crate::fs::fd::fd_read_at(fd as i32, kernel_buf.as_mut_ptr(), count as usize, offset as usize) {
        Ok(bytes) => {
            if copy_to_user(buf, &kernel_buf[..bytes]).is_err() {
                return EFAULT as u64;
            }
            bytes as u64
        }
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_pwrite64(fd: u64, buf: u64, count: u64, offset: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return EFAULT as u64;
    }
    if validate_user_read(buf, count as usize).is_err() {
        return EFAULT as u64;
    }

    let mut kernel_buf = alloc::vec![0u8; count as usize];
    if copy_from_user(&mut kernel_buf, buf).is_err() {
        return EFAULT as u64;
    }

    let current_pos = match crate::fs::fd::fd_lseek(fd as i32, 0, 1) {
        Ok(pos) => pos,
        Err(e) => return e.to_errno() as u64,
    };

    if let Err(e) = crate::fs::fd::fd_lseek(fd as i32, offset as i64, 0) {
        return e.to_errno() as u64;
    }

    let result = crate::fs::fd::fd_write(fd as i32, kernel_buf.as_ptr(), count as usize);
    let _ = crate::fs::fd::fd_lseek(fd as i32, current_pos, 0);

    match result {
        Ok(bytes) => bytes as u64,
        Err(e) => e.to_errno() as u64,
    }
}
