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

use crate::syscall::dispatch::process as p;
use crate::syscall::dispatch::util::errno;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

pub(super) fn dispatch_process(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Exit | SyscallNumber::ExitGroup => p::handle_exit(a0),
        SyscallNumber::Fork | SyscallNumber::Vfork => p::handle_fork(),
        SyscallNumber::Clone => crate::syscall::extended::handle_clone(a0, a1, a2, a3, a4),
        SyscallNumber::Execve => p::handle_execve(a0, a1, a2),
        SyscallNumber::Execveat => {
            crate::syscall::extended::handle_execveat(a0 as i32, a1, a2, a3, a4 as i32)
        }
        SyscallNumber::Wait4 => crate::syscall::extended::handle_wait4(a0 as i64, a1, a2, a3),
        SyscallNumber::Waitid => crate::syscall::extended::handle_waitid(a0, a1, a2, a3, a4),
        SyscallNumber::Nanosleep => p::handle_nanosleep(a0, a1),
        SyscallNumber::ClockNanosleep => {
            crate::syscall::extended::handle_clock_nanosleep(a0, a1, a2, a3)
        }
        SyscallNumber::Yield => p::handle_yield(),
        SyscallNumber::Futex => {
            crate::syscall::extended::sync::handle_futex(a0, a1 as i32, a2, a3, a4, a5)
        }
        SyscallNumber::Prctl => crate::syscall::extended::handle_prctl(a0 as i32, a1, a2, a3, a4),
        SyscallNumber::ArchPrctl => crate::syscall::extended::handle_arch_prctl(a0 as i32, a1),
        SyscallNumber::SetTidAddress => crate::syscall::extended::handle_set_tid_address(a0),
        SyscallNumber::Seccomp => {
            crate::syscall::extended::handle_seccomp(a0 as u32, a1 as u32, a2)
        }
        SyscallNumber::Getpid => p::handle_getpid(),
        SyscallNumber::Getppid => crate::syscall::extended::handle_getppid(),
        SyscallNumber::Gettid => crate::syscall::extended::handle_gettid(),
        SyscallNumber::Getpgrp => crate::syscall::extended::handle_getpgrp(),
        SyscallNumber::Getpgid => crate::syscall::extended::handle_getpgid(a0 as i32),
        SyscallNumber::Setpgid => crate::syscall::extended::handle_setpgid(a0 as i32, a1 as i32),
        SyscallNumber::Getsid => crate::syscall::extended::handle_getsid(a0 as i32),
        SyscallNumber::Setsid => crate::syscall::extended::handle_setsid(),
        SyscallNumber::Getuid => crate::syscall::extended::handle_getuid(),
        SyscallNumber::Geteuid => crate::syscall::extended::handle_geteuid(),
        SyscallNumber::Getgid => crate::syscall::extended::handle_getgid(),
        SyscallNumber::Getegid => crate::syscall::extended::handle_getegid(),
        SyscallNumber::Setuid => crate::syscall::extended::handle_setuid(a0 as u32),
        SyscallNumber::Setgid => crate::syscall::extended::handle_setgid(a0 as u32),
        SyscallNumber::Setreuid => crate::syscall::extended::handle_setreuid(a0 as u32, a1 as u32),
        SyscallNumber::Setregid => crate::syscall::extended::handle_setregid(a0 as u32, a1 as u32),
        SyscallNumber::Getresuid => crate::syscall::extended::handle_getresuid(a0, a1, a2),
        SyscallNumber::Setresuid => {
            crate::syscall::extended::handle_setresuid(a0 as u32, a1 as u32, a2 as u32)
        }
        SyscallNumber::Getresgid => crate::syscall::extended::handle_getresgid(a0, a1, a2),
        SyscallNumber::Setresgid => {
            crate::syscall::extended::handle_setresgid(a0 as u32, a1 as u32, a2 as u32)
        }
        SyscallNumber::Setfsuid => crate::syscall::extended::handle_setfsuid(a0 as u32),
        SyscallNumber::Setfsgid => crate::syscall::extended::handle_setfsgid(a0 as u32),
        SyscallNumber::Getgroups => crate::syscall::extended::handle_getgroups(a0 as i32, a1),
        SyscallNumber::Setgroups => crate::syscall::extended::handle_setgroups(a0, a1),
        SyscallNumber::Capget => crate::syscall::extended::handle_capget(a0, a1),
        SyscallNumber::Capset => crate::syscall::extended::handle_capset(a0, a1),
        SyscallNumber::CapDrop => {
            let value = crate::process::capabilities::drop::sys_cap_drop(a0);
            SyscallResult { value, capability_consumed: false, audit_required: true }
        }
        _ => errno(38),
    }
}
