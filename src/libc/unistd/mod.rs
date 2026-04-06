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

pub use syscall::syscall;
pub use read::read;
pub use write::write;
pub use fork::{fork, vfork, execve, execvp, _exit, getpid, getppid, getuid, getgid, geteuid, getegid};

#[no_mangle]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    crate::syscall::sys_close(fd as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn dup(oldfd: i32) -> i32 {
    crate::syscall::sys_dup(oldfd as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 {
    crate::syscall::sys_dup2(oldfd as usize, newfd as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn pipe(pipefd: *mut i32) -> i32 {
    crate::syscall::sys_pipe(pipefd as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    crate::syscall::sys_lseek(fd as usize, offset, whence as usize)
}

#[no_mangle]
pub unsafe extern "C" fn chdir(path: *const u8) -> i32 {
    crate::syscall::sys_chdir(path as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    let ret = crate::syscall::sys_getcwd(buf as usize, size);
    if ret < 0 { core::ptr::null_mut() } else { buf }
}

#[no_mangle]
pub unsafe extern "C" fn unlink(path: *const u8) -> i32 {
    crate::syscall::sys_unlink(path as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn rmdir(path: *const u8) -> i32 {
    crate::syscall::sys_rmdir(path as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn access(path: *const u8, mode: i32) -> i32 {
    crate::syscall::sys_access(path as usize, mode as usize) as i32
}

#[no_mangle]
pub unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    let ts = crate::libc::time::Timespec { tv_sec: seconds as i64, tv_nsec: 0 };
    crate::libc::time::nanosleep(&ts, core::ptr::null_mut());
    0
}

#[no_mangle]
pub unsafe extern "C" fn usleep(usec: u32) -> i32 {
    let ts = crate::libc::time::Timespec { tv_sec: (usec / 1_000_000) as i64, tv_nsec: ((usec % 1_000_000) * 1000) as i64 };
    crate::libc::time::nanosleep(&ts, core::ptr::null_mut())
}
