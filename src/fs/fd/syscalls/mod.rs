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

mod directory;
mod memfd;
mod open;
mod read;
mod seek;
mod stat;
mod stdio;
mod sync;
mod write;

pub use directory::{mkdir_syscall, rename_syscall, rmdir_syscall, unlink_syscall};
pub use memfd::create_memfd;
pub use open::{close_file_descriptor, open_file_create, open_file_syscall};
pub use read::{fd_read, fd_read_at, read_file_descriptor};
pub use seek::{fd_lseek, lseek_syscall};
pub use stat::{fd_fstat, fstat_file_syscall, stat_file_syscall, KernelStat};
pub use sync::{fd_allocate, fd_chmod, fd_chown, fd_sync, sync_all};
pub use write::{fd_write, fd_write_at, write_file_descriptor};

#[deprecated(note = "Use fd_read instead")]
pub fn fd_read_legacy(fd: i32, buf: *mut u8, count: usize) -> Result<usize, &'static str> {
    fd_read(fd, buf, count).map_err(|e| e.as_str())
}

#[deprecated(note = "Use fd_write instead")]
pub fn fd_write_legacy(fd: i32, buf: *const u8, count: usize) -> Result<usize, &'static str> {
    fd_write(fd, buf, count).map_err(|e| e.as_str())
}
