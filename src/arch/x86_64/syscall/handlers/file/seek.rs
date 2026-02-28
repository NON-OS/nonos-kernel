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

pub fn syscall_lseek(fd: u64, offset: u64, whence: u64, _: u64, _: u64, _: u64) -> u64 {
    match crate::fs::nonos_vfs::vfs_lseek(fd as u32, offset as i64, whence as u32) {
        Ok(pos) => pos as u64,
        Err(_) => (-9i64) as u64,
    }
}

pub fn syscall_pread64(fd: u64, buf: u64, count: u64, offset: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return (-14i64) as u64;
    }

    match crate::fs::fd::fd_read_at(fd as i32, buf as *mut u8, count as usize, offset as usize) {
        Ok(bytes) => bytes as u64,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_pwrite64(fd: u64, buf: u64, count: u64, offset: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return (-14i64) as u64;
    }

    let current_pos = match crate::fs::fd::fd_lseek(fd as i32, 0, 1) {
        Ok(pos) => pos,
        Err(e) => return e.to_errno() as u64,
    };

    if let Err(e) = crate::fs::fd::fd_lseek(fd as i32, offset as i64, 0) {
        return e.to_errno() as u64;
    }

    let result = crate::fs::fd::fd_write(fd as i32, buf as *const u8, count as usize);
    let _ = crate::fs::fd::fd_lseek(fd as i32, current_pos, 0);

    match result {
        Ok(bytes) => bytes as u64,
        Err(e) => e.to_errno() as u64,
    }
}
