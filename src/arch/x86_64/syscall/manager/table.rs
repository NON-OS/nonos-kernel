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

extern crate alloc;

use alloc::vec::Vec;

use crate::arch::x86_64::syscall::numbers::*;
use crate::arch::x86_64::syscall::handlers;
use super::core::SyscallManager;
use super::types::SyscallInfo;

impl SyscallManager {
    pub(crate) fn initialize_table(&self) {
        let mut table = self.table.write();

        table.insert(SYS_READ, SyscallInfo::new(SYS_READ, "read", handlers::syscall_read));
        table.insert(SYS_WRITE, SyscallInfo::new(SYS_WRITE, "write", handlers::syscall_write));
        table.insert(SYS_OPEN, SyscallInfo::new(SYS_OPEN, "open", handlers::syscall_open));
        table.insert(SYS_CLOSE, SyscallInfo::new(SYS_CLOSE, "close", handlers::syscall_close));
        table.insert(SYS_LSEEK, SyscallInfo::new(SYS_LSEEK, "lseek", handlers::syscall_lseek));
        table.insert(SYS_PREAD64, SyscallInfo::new(SYS_PREAD64, "pread64", handlers::syscall_pread64));
        table.insert(SYS_PWRITE64, SyscallInfo::new(SYS_PWRITE64, "pwrite64", handlers::syscall_pwrite64));

        table.insert(SYS_STAT, SyscallInfo::new(SYS_STAT, "stat", handlers::syscall_stat));
        table.insert(SYS_FSTAT, SyscallInfo::new(SYS_FSTAT, "fstat", handlers::syscall_fstat));
        table.insert(SYS_LSTAT, SyscallInfo::new(SYS_LSTAT, "lstat", handlers::syscall_lstat));

        table.insert(SYS_MMAP, SyscallInfo::new(SYS_MMAP, "mmap", handlers::syscall_mmap));
        table.insert(SYS_MPROTECT, SyscallInfo::new(SYS_MPROTECT, "mprotect", handlers::syscall_mprotect));
        table.insert(SYS_MUNMAP, SyscallInfo::new(SYS_MUNMAP, "munmap", handlers::syscall_munmap));
        table.insert(SYS_BRK, SyscallInfo::new(SYS_BRK, "brk", handlers::syscall_brk));

        table.insert(SYS_GETPID, SyscallInfo::new(SYS_GETPID, "getpid", handlers::syscall_getpid));
        table.insert(SYS_GETPPID, SyscallInfo::new(SYS_GETPPID, "getppid", handlers::syscall_getppid));
        table.insert(SYS_GETUID, SyscallInfo::new(SYS_GETUID, "getuid", handlers::syscall_getuid));
        table.insert(SYS_GETGID, SyscallInfo::new(SYS_GETGID, "getgid", handlers::syscall_getgid));
        table.insert(SYS_GETEUID, SyscallInfo::new(SYS_GETEUID, "geteuid", handlers::syscall_geteuid));
        table.insert(SYS_GETEGID, SyscallInfo::new(SYS_GETEGID, "getegid", handlers::syscall_getegid));
        table.insert(SYS_FORK, SyscallInfo::new(SYS_FORK, "fork", handlers::syscall_fork));
        table.insert(SYS_CLONE, SyscallInfo::new(SYS_CLONE, "clone", handlers::syscall_clone));
        table.insert(SYS_EXECVE, SyscallInfo::new(SYS_EXECVE, "execve", handlers::syscall_execve));
        table.insert(SYS_EXIT, SyscallInfo::new(SYS_EXIT, "exit", handlers::syscall_exit));
        table.insert(SYS_WAIT4, SyscallInfo::new(SYS_WAIT4, "wait4", handlers::syscall_wait4));

        table.insert(SYS_RT_SIGACTION, SyscallInfo::new(SYS_RT_SIGACTION, "rt_sigaction", handlers::syscall_rt_sigaction));
        table.insert(SYS_RT_SIGPROCMASK, SyscallInfo::new(SYS_RT_SIGPROCMASK, "rt_sigprocmask", handlers::syscall_rt_sigprocmask));
        table.insert(SYS_RT_SIGRETURN, SyscallInfo::new(SYS_RT_SIGRETURN, "rt_sigreturn", handlers::syscall_rt_sigreturn));
        table.insert(SYS_KILL, SyscallInfo::new(SYS_KILL, "kill", handlers::syscall_kill));

        table.insert(SYS_IOCTL, SyscallInfo::new(SYS_IOCTL, "ioctl", handlers::syscall_ioctl));

        table.insert(SYS_DUP, SyscallInfo::new(SYS_DUP, "dup", handlers::syscall_dup));
        table.insert(SYS_DUP2, SyscallInfo::new(SYS_DUP2, "dup2", handlers::syscall_dup2));
        table.insert(SYS_PIPE, SyscallInfo::new(SYS_PIPE, "pipe", handlers::syscall_pipe));

        table.insert(SYS_NONOSLEEP, SyscallInfo::new(SYS_NONOSLEEP, "nanosleep", handlers::syscall_nanosleep));
        table.insert(SYS_SCHED_YIELD, SyscallInfo::new(SYS_SCHED_YIELD, "sched_yield", handlers::syscall_sched_yield));
        table.insert(SYS_ALARM, SyscallInfo::new(SYS_ALARM, "alarm", handlers::syscall_alarm));

        table.insert(SYS_UNAME, SyscallInfo::new(SYS_UNAME, "uname", handlers::syscall_uname));

        table.insert(SYS_SOCKET, SyscallInfo::new(SYS_SOCKET, "socket", handlers::syscall_socket));
        table.insert(SYS_CONNECT, SyscallInfo::new(SYS_CONNECT, "connect", handlers::syscall_connect));
        table.insert(SYS_ACCEPT, SyscallInfo::new(SYS_ACCEPT, "accept", handlers::syscall_accept));
        table.insert(SYS_BIND, SyscallInfo::new(SYS_BIND, "bind", handlers::syscall_bind));
        table.insert(SYS_LISTEN, SyscallInfo::new(SYS_LISTEN, "listen", handlers::syscall_listen));
        table.insert(SYS_SENDTO, SyscallInfo::new(SYS_SENDTO, "sendto", handlers::syscall_sendto));
        table.insert(SYS_RECVFROM, SyscallInfo::new(SYS_RECVFROM, "recvfrom", handlers::syscall_recvfrom));
    }

    pub(crate) fn compute_table_hash(&self) {
        let table = self.table.read();
        let mut data = Vec::new();

        for (num, info) in table.iter() {
            data.extend_from_slice(&num.to_le_bytes());
            data.extend_from_slice(&(info.handler as *const () as u64).to_le_bytes());
        }

        let hash = crate::crypto::hash::sha3_256(&data);
        let mut original = self.original_hash.write();
        *original = hash;
    }
}
