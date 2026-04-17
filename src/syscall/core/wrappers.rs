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

use crate::syscall::{handle_syscall, SyscallNumber};

#[inline]
pub fn sys_open(path_ptr: u64, flags: u64, mode: u64) -> i64 {
    handle_syscall(SyscallNumber::Open as u64, path_ptr, flags, mode, 0, 0, 0) as i64
}

#[inline]
pub fn sys_read(fd: u64, buf: u64, len: u64) -> i64 {
    handle_syscall(SyscallNumber::Read as u64, fd, buf, len, 0, 0, 0) as i64
}

#[inline]
pub fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    handle_syscall(SyscallNumber::Write as u64, fd, buf, len, 0, 0, 0) as i64
}

#[inline]
pub fn sys_close(fd: u64) -> i64 {
    handle_syscall(SyscallNumber::Close as u64, fd, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_stat(path_ptr: u64, statbuf: u64) -> i64 {
    handle_syscall(SyscallNumber::Stat as u64, path_ptr, statbuf, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_fstat(fd: u64, statbuf: u64) -> i64 {
    handle_syscall(SyscallNumber::Fstat as u64, fd, statbuf, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_lseek(fd: u64, offset: u64, whence: u64) -> i64 {
    handle_syscall(SyscallNumber::Lseek as u64, fd, offset, whence, 0, 0, 0) as i64
}

#[inline]
pub fn sys_mkdir(path_ptr: u64, mode: u64) -> i64 {
    handle_syscall(SyscallNumber::Mkdir as u64, path_ptr, mode, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rmdir(path_ptr: u64) -> i64 {
    handle_syscall(SyscallNumber::Rmdir as u64, path_ptr, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_unlink(path_ptr: u64) -> i64 {
    handle_syscall(SyscallNumber::Unlink as u64, path_ptr, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rename(old_ptr: u64, new_ptr: u64) -> i64 {
    handle_syscall(SyscallNumber::Rename as u64, old_ptr, new_ptr, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_access(path_ptr: usize, mode: i32) -> i64 {
    handle_syscall(SyscallNumber::Access as u64, path_ptr as u64, mode as u64, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_arch_prctl(code: u64, addr: usize) -> i64 {
    handle_syscall(SyscallNumber::ArchPrctl as u64, code, addr as u64, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_futex(uaddr: u64, op: u32, val: u32, timeout: u64, uaddr2: u64, val3: u32) -> i64 {
    handle_syscall(SyscallNumber::Futex as u64, uaddr, op as u64, val as u64, timeout, uaddr2, val3 as u64) as i64
}

#[inline]
pub fn sys_fork() -> i64 {
    handle_syscall(SyscallNumber::Fork as u64, 0, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_clone(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> i64 {
    handle_syscall(SyscallNumber::Clone as u64, flags, stack, ptid, ctid, tls, 0) as i64
}

#[inline]
pub fn sys_execve(path: u64, argv: u64, envp: u64) -> i64 {
    handle_syscall(SyscallNumber::Execve as u64, path, argv, envp, 0, 0, 0) as i64
}

#[inline]
pub fn sys_exit(code: i32) -> ! {
    handle_syscall(SyscallNumber::Exit as u64, code as u64, 0, 0, 0, 0, 0);
    crate::arch::x86_64::boot::cpu_ops::halt_loop()
}

#[inline]
pub fn sys_getpid() -> i64 {
    handle_syscall(SyscallNumber::Getpid as u64, 0, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_getppid() -> i64 {
    handle_syscall(SyscallNumber::Getppid as u64, 0, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_kill(pid: i64, sig: i32) -> i64 {
    handle_syscall(SyscallNumber::Kill as u64, pid as u64, sig as u64, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rt_sigaction(sig: i32, act: u64, oact: u64, sigsetsize: u64) -> i64 {
    handle_syscall(SyscallNumber::RtSigaction as u64, sig as u64, act, oact, sigsetsize, 0, 0) as i64
}

#[inline]
pub fn sys_rt_sigprocmask(how: i32, set: u64, oldset: u64, sigsetsize: u64) -> i64 {
    handle_syscall(SyscallNumber::RtSigprocmask as u64, how as u64, set, oldset, sigsetsize, 0, 0) as i64
}

#[inline]
pub fn sys_rt_sigpending(set: u64, sigsetsize: u64) -> i64 {
    handle_syscall(SyscallNumber::RtSigpending as u64, set, sigsetsize, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_rt_sigsuspend(mask: u64, sigsetsize: u64) -> i64 {
    handle_syscall(SyscallNumber::RtSigsuspend as u64, mask, sigsetsize, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_nanosleep(rqtp: u64, rmtp: u64) -> i64 {
    handle_syscall(SyscallNumber::Nanosleep as u64, rqtp, rmtp, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_clock_gettime(clk_id: i32, tp: u64) -> i64 {
    handle_syscall(SyscallNumber::ClockGettime as u64, clk_id as u64, tp, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_clock_settime(clk_id: i32, tp: u64) -> i64 {
    handle_syscall(SyscallNumber::ClockSettime as u64, clk_id as u64, tp, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_clock_getres(clk_id: i32, res: u64) -> i64 {
    handle_syscall(SyscallNumber::ClockGetres as u64, clk_id as u64, res, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_clock_nanosleep(clk_id: i32, flags: i32, rqtp: u64, rmtp: u64) -> i64 {
    handle_syscall(SyscallNumber::ClockNanosleep as u64, clk_id as u64, flags as u64, rqtp, rmtp, 0, 0) as i64
}

#[inline]
pub fn sys_pread64(fd: u64, buf: u64, count: u64, offset: i64) -> i64 {
    handle_syscall(SyscallNumber::Pread64 as u64, fd, buf, count, offset as u64, 0, 0) as i64
}

#[inline]
pub fn sys_pwrite64(fd: u64, buf: u64, count: u64, offset: i64) -> i64 {
    handle_syscall(SyscallNumber::Pwrite64 as u64, fd, buf, count, offset as u64, 0, 0) as i64
}

#[inline]
pub fn sys_readv(fd: u64, iov: u64, iovcnt: i32) -> i64 {
    handle_syscall(SyscallNumber::Readv as u64, fd, iov, iovcnt as u64, 0, 0, 0) as i64
}

#[inline]
pub fn sys_writev(fd: u64, iov: u64, iovcnt: i32) -> i64 {
    handle_syscall(SyscallNumber::Writev as u64, fd, iov, iovcnt as u64, 0, 0, 0) as i64
}

#[inline]
pub fn sys_preadv(fd: u64, iov: u64, iovcnt: i32, offset: i64) -> i64 {
    handle_syscall(SyscallNumber::Preadv as u64, fd, iov, iovcnt as u64, offset as u64, 0, 0) as i64
}

#[inline]
pub fn sys_pwritev(fd: u64, iov: u64, iovcnt: i32, offset: i64) -> i64 {
    handle_syscall(SyscallNumber::Pwritev as u64, fd, iov, iovcnt as u64, offset as u64, 0, 0) as i64
}

#[inline]
pub fn sys_getuid() -> i64 {
    handle_syscall(SyscallNumber::Getuid as u64, 0, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_getgid() -> i64 {
    handle_syscall(SyscallNumber::Getgid as u64, 0, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_geteuid() -> i64 {
    handle_syscall(SyscallNumber::Geteuid as u64, 0, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_getegid() -> i64 {
    handle_syscall(SyscallNumber::Getegid as u64, 0, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_setuid(uid: usize) -> i64 {
    handle_syscall(SyscallNumber::Setuid as u64, uid as u64, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_setgid(gid: usize) -> i64 {
    handle_syscall(SyscallNumber::Setgid as u64, gid as u64, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_dup(oldfd: usize) -> i64 {
    handle_syscall(SyscallNumber::Dup as u64, oldfd as u64, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_dup2(oldfd: usize, newfd: usize) -> i64 {
    handle_syscall(SyscallNumber::Dup2 as u64, oldfd as u64, newfd as u64, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_pipe(pipefd: usize) -> i64 {
    handle_syscall(SyscallNumber::Pipe as u64, pipefd as u64, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_chdir(path: usize) -> i64 {
    handle_syscall(SyscallNumber::Chdir as u64, path as u64, 0, 0, 0, 0, 0) as i64
}

#[inline]
pub fn sys_getcwd(buf: usize, size: usize) -> i64 {
    handle_syscall(SyscallNumber::Getcwd as u64, buf as u64, size as u64, 0, 0, 0, 0) as i64
}
