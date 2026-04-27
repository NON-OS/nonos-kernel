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

pub mod aio;
pub mod bpf;
pub mod caps;
pub mod core;
pub mod dispatch;
pub mod entry;
pub mod epoll;
pub mod extended;
pub mod fanotify;
pub mod handler;
pub mod keyring;
pub mod microkernel;
pub mod mqueue;
pub mod namespace;
pub mod numbers;
pub mod pkey;
pub mod poll;
pub mod process_vm;
pub mod ptrace;
pub mod robust_futex;
pub mod rseq;
pub mod seccomp;
pub mod service_ipc;
pub mod signals;
pub mod splice;
pub mod tls;
pub mod types;
pub mod validation;
pub mod vdso;
pub mod xattr;

#[cfg(test)]
#[cfg(test)]
mod tests;

pub use caps as capabilities;
pub use caps::current_caps;
pub use core::{
    sys_access, sys_arch_prctl, sys_brk, sys_chdir, sys_clock_getres, sys_clock_gettime,
    sys_clock_nanosleep, sys_clock_settime, sys_clone, sys_close, sys_dup, sys_dup2, sys_execve,
    sys_exit, sys_fork, sys_fstat, sys_futex, sys_getcwd, sys_getegid, sys_geteuid, sys_getgid,
    sys_getpid, sys_getppid, sys_getuid, sys_ioctl, sys_kill, sys_lseek, sys_mkdir, sys_mmap,
    sys_munmap, sys_nanosleep, sys_open, sys_openat, sys_pipe, sys_pread64, sys_preadv,
    sys_pwrite64, sys_pwritev, sys_read, sys_readv, sys_rename, sys_rmdir, sys_rt_sigaction,
    sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigsuspend, sys_setgid, sys_setuid, sys_stat,
    sys_unlink, sys_waitpid, sys_write, sys_writev,
};
pub use dispatch::handle_syscall_dispatch;
pub use entry::{handle_interrupt, handle_syscall};
pub use numbers::SyscallNumber;
pub use types::{errno, errnos, SyscallResult};
