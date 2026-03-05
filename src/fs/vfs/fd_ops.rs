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

use core::sync::atomic::{Ordering, compiler_fence};

use super::error::VfsResult;
use super::table::FD_TABLE;
use super::types::{IoStatistics, OpenFlags};

pub fn vfs_open(path: &str, flags: OpenFlags) -> VfsResult<u32> {
    FD_TABLE.write().open(path, flags)
}

pub fn vfs_close(fd: u32) -> VfsResult<()> {
    FD_TABLE.write().close(fd)
}

pub fn vfs_read(fd: u32, buffer: &mut [u8]) -> VfsResult<usize> {
    FD_TABLE.write().read(fd, buffer)
}

pub fn vfs_write(fd: u32, buffer: &[u8]) -> VfsResult<usize> {
    FD_TABLE.write().write(fd, buffer)
}

pub fn vfs_lseek(fd: u32, offset: i64, whence: u32) -> VfsResult<u64> {
    FD_TABLE.write().lseek(fd, offset, whence)
}

pub fn vfs_fd_exists(fd: u32) -> bool {
    FD_TABLE.read().files.contains_key(&fd)
}

pub fn vfs_io_stats() -> IoStatistics {
    FD_TABLE.read().get_stats()
}

pub fn clear_fd_table() {
    FD_TABLE.write().clear_all();
    compiler_fence(Ordering::SeqCst);
}

pub fn vfs_open_legacy(path: &str, flags: OpenFlags) -> Result<u32, &'static str> {
    vfs_open(path, flags).map_err(|e| e.as_str())
}

pub fn vfs_close_legacy(fd: u32) -> Result<(), &'static str> {
    vfs_close(fd).map_err(|e| e.as_str())
}

pub fn vfs_read_legacy(fd: u32, buffer: &mut [u8]) -> Result<usize, &'static str> {
    vfs_read(fd, buffer).map_err(|e| e.as_str())
}

pub fn vfs_write_legacy(fd: u32, buffer: &[u8]) -> Result<usize, &'static str> {
    vfs_write(fd, buffer).map_err(|e| e.as_str())
}

pub fn vfs_lseek_legacy(fd: u32, offset: i64, whence: u32) -> Result<u64, &'static str> {
    vfs_lseek(fd, offset, whence).map_err(|e| e.as_str())
}

pub fn vfs_read_secure(fd: u32, buffer: &mut [u8]) -> VfsResult<usize> {
    FD_TABLE.write().read_secure(fd, buffer)
}

pub fn vfs_secure_clear_buffer(buffer: &mut [u8]) {
    FD_TABLE.read().secure_clear_buffer(buffer)
}
