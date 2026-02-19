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

mod stdio;
mod read;
mod write;
mod seek;
mod stat;
mod directory;
mod sync;
mod memfd;
mod open;

pub use read::{read_file_descriptor, fd_read, fd_read_at};
pub use write::{write_file_descriptor, fd_write, fd_write_at};
pub use seek::{lseek_syscall, fd_lseek};
pub use stat::{stat_file_syscall, fstat_file_syscall, fd_fstat, KernelStat};
pub use directory::{mkdir_syscall, rename_syscall, rmdir_syscall, unlink_syscall};
pub use sync::{fd_sync, fd_allocate, fd_chmod, fd_chown, sync_all};
pub use memfd::create_memfd;
pub use open::{open_file_syscall, open_file_create, close_file_descriptor};

#[deprecated(note = "Use fd_read instead")]
pub fn fd_read_legacy(fd: i32, buf: *mut u8, count: usize) -> Result<usize, &'static str> {
    fd_read(fd, buf, count).map_err(|e| e.as_str())
}

#[deprecated(note = "Use fd_write instead")]
pub fn fd_write_legacy(fd: i32, buf: *const u8, count: usize) -> Result<usize, &'static str> {
    fd_write(fd, buf, count).map_err(|e| e.as_str())
}
