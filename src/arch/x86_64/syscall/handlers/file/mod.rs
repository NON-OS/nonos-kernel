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

mod read_write;
mod open_close;
mod seek;
mod stat;
mod misc;

pub use read_write::{syscall_read, syscall_write};
pub use open_close::{syscall_open, syscall_close};
pub use seek::{syscall_lseek, syscall_pread64, syscall_pwrite64};
pub use stat::{syscall_stat, syscall_fstat, syscall_lstat};
pub use misc::{syscall_dup, syscall_dup2, syscall_pipe, syscall_ioctl};
