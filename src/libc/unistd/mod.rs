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

mod fd_ops;
pub mod fork;
mod path_ops;
pub mod read;
mod sleep;
pub mod syscall;
pub mod write;

pub use fd_ops::{close, dup, dup2, ioctl, lseek, open, pipe};
pub use fork::{
    _exit, execve, execvp, fork, getegid, geteuid, getgid, getpid, getppid, getuid, vfork, wait,
    waitpid,
};
pub use path_ops::{access, chdir, getcwd, rmdir, unlink};
pub use read::read;
pub use sleep::{sleep, usleep};
pub use syscall::syscall;
pub use write::write;
