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

mod misc;
mod open_close;
mod read;
mod read_stdin;
mod seek;
mod stat;
mod write;
mod write_stdout;

pub use misc::{syscall_dup, syscall_dup2, syscall_ioctl, syscall_pipe};
pub use open_close::{syscall_close, syscall_open};
pub use read::syscall_read;
pub use seek::{syscall_lseek, syscall_pread64, syscall_pwrite64};
pub use stat::{syscall_fstat, syscall_lstat, syscall_stat};
pub use write::syscall_write;
