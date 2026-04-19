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

use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn fork() -> i32 {
    let ret = crate::syscall::sys_fork();
    if ret < 0 { crate::libc::errno::set_errno((-ret) as i32); return -1; }
    ret as i32
}

#[no_mangle]
pub unsafe extern "C" fn vfork() -> i32 {
    fork()
}

#[no_mangle]
pub unsafe extern "C" fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    let ret = crate::syscall::sys_execve(path as u64, argv as u64, envp as u64);
    if ret < 0 { crate::libc::errno::set_errno((-ret) as i32); }
    -1
}

#[no_mangle]
pub unsafe extern "C" fn execvp(file: *const u8, argv: *const *const u8) -> i32 {
    if file.is_null() { crate::libc::errno::set_errno(22); return -1; }
    let path_env = crate::libc::stdlib::env::getenv(b"/usr/bin:/bin\0".as_ptr());
    let paths = if path_env.is_null() { b"/usr/bin:/bin\0".as_ptr() } else { path_env };
    let file_len = crate::libc::string::strlen::strlen(file);
    let has_slash = (0..file_len).any(|i| ptr::read(file.add(i)) == b'/');
    if has_slash { return execve(file, argv, crate::libc::stdlib::env::environ_ptr()); }
    let mut buf = [0u8; 256];
    let mut start = 0usize;
    let paths_len = crate::libc::string::strlen::strlen(paths);
    for i in 0..=paths_len {
        let c = if i < paths_len { ptr::read(paths.add(i)) } else { 0 };
        if c == b':' || c == 0 {
            let plen = i - start;
            if plen + 1 + file_len + 1 <= buf.len() {
                crate::libc::string::memcpy::memcpy(buf.as_mut_ptr(), paths.add(start), plen);
                buf[plen] = b'/';
                crate::libc::string::memcpy::memcpy(buf.as_mut_ptr().add(plen + 1), file, file_len);
                buf[plen + 1 + file_len] = 0;
                let ret = execve(buf.as_ptr(), argv, crate::libc::stdlib::env::environ_ptr());
                if ret == 0 { return 0; }
            }
            start = i + 1;
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn _exit(status: i32) -> ! {
    crate::syscall::sys_exit(status);
}

#[no_mangle]
pub unsafe extern "C" fn getpid() -> i32 { crate::syscall::sys_getpid() as i32 }

#[no_mangle]
pub unsafe extern "C" fn getppid() -> i32 { crate::syscall::sys_getppid() as i32 }

#[no_mangle]
pub unsafe extern "C" fn getuid() -> u32 { crate::syscall::sys_getuid() as u32 }

#[no_mangle]
pub unsafe extern "C" fn getgid() -> u32 { crate::syscall::sys_getgid() as u32 }

#[no_mangle]
pub unsafe extern "C" fn geteuid() -> u32 { crate::syscall::sys_geteuid() as u32 }

#[no_mangle]
pub unsafe extern "C" fn getegid() -> u32 { crate::syscall::sys_getegid() as u32 }

#[no_mangle]
pub unsafe extern "C" fn setuid(uid: u32) -> i32 { crate::syscall::sys_setuid(uid as usize) as i32 }

#[no_mangle]
pub unsafe extern "C" fn setgid(gid: u32) -> i32 { crate::syscall::sys_setgid(gid as usize) as i32 }

#[no_mangle]
pub unsafe extern "C" fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32 {
    let ret = crate::syscall::sys_waitpid(pid as i64, status as u64, options as u64);
    if ret < 0 { crate::libc::errno::set_errno((-ret) as i32); return -1; }
    ret as i32
}

#[no_mangle]
pub unsafe extern "C" fn wait(status: *mut i32) -> i32 {
    waitpid(-1, status, 0)
}
