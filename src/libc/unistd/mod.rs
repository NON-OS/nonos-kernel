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

pub mod syscall;
pub mod read;
pub mod write;
pub mod fork;
mod fd_ops;
mod path_ops;
mod sleep;

pub use syscall::syscall;
pub use read::read;
pub use write::write;
pub use fork::{fork, vfork, execve, execvp, _exit, getpid, getppid, getuid, getgid, geteuid, getegid, waitpid, wait};
pub use fd_ops::{close, dup, dup2, pipe, lseek, open, ioctl};
pub use path_ops::{chdir, getcwd, unlink, rmdir, access};
pub use sleep::{sleep, usleep};
