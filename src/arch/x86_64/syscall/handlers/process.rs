// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub fn syscall_getpid(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_getpid();
    result.value as u64
}

pub fn syscall_getppid(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_getppid();
    result.value as u64
}

pub fn syscall_getuid(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_getuid();
    result.value as u64
}

pub fn syscall_getgid(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_getgid();
    result.value as u64
}

pub fn syscall_geteuid(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_geteuid();
    result.value as u64
}

pub fn syscall_getegid(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_getegid();
    result.value as u64
}

pub fn syscall_gettid(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_gettid();
    result.value as u64
}

pub fn syscall_fork(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_fork();
    result.value as u64
}

pub fn syscall_clone(flags: u64, stack: u64, parent_tid: u64, child_tid: u64, tls: u64, _: u64) -> u64 {
    // Full clone implementation supporting CLONE_VM (threads) and other flags
    match crate::process::clone_process(flags, stack, parent_tid, child_tid, tls) {
        Ok(tid) => tid as u64,
        Err(errno) => errno as u64,
    }
}

pub fn syscall_execve(pathname: u64, argv: u64, envp: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_execve(pathname, argv, envp);
    result.value as u64
}

pub fn syscall_exit(status: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_exit(status);
    result.value as u64
}

pub fn syscall_exit_group(status: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::dispatch::process::handle_exit(status);
    result.value as u64
}

pub fn syscall_wait4(pid: u64, wstatus: u64, options: u64, rusage: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_wait4(pid as i64, wstatus, options, rusage);
    result.value as u64
}

pub fn syscall_waitid(idtype: u64, id: u64, infop: u64, options: u64, rusage: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::process::handle_waitid(idtype, id, infop, options, rusage);
    result.value as u64
}
