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

use crate::capabilities::CapabilityToken;
use crate::syscall::numbers::SyscallNumber;

pub(super) fn check(caps: &CapabilityToken, number: SyscallNumber) -> Option<bool> {
    Some(match number {
        SyscallNumber::Exit | SyscallNumber::ExitGroup => caps.can_exit(),
        SyscallNumber::Fork | SyscallNumber::Vfork | SyscallNumber::Clone => caps.can_fork(),
        SyscallNumber::Execve | SyscallNumber::Execveat => caps.can_exec(),
        SyscallNumber::Wait4 | SyscallNumber::Waitid => caps.can_wait(),

        SyscallNumber::Nanosleep
        | SyscallNumber::ClockNanosleep
        | SyscallNumber::Yield
        | SyscallNumber::Futex
        | SyscallNumber::Prctl
        | SyscallNumber::ArchPrctl
        | SyscallNumber::SetTidAddress
        | SyscallNumber::Getppid
        | SyscallNumber::Gettid
        | SyscallNumber::Getpgrp
        | SyscallNumber::Getpgid
        | SyscallNumber::Setpgid
        | SyscallNumber::Getsid
        | SyscallNumber::Setsid
        | SyscallNumber::Getuid
        | SyscallNumber::Geteuid
        | SyscallNumber::Getgid
        | SyscallNumber::Getegid
        | SyscallNumber::Getresuid
        | SyscallNumber::Getresgid
        | SyscallNumber::Getgroups
        | SyscallNumber::Capget
        | SyscallNumber::Capset
        | SyscallNumber::Umask
        | SyscallNumber::SchedSetparam
        | SyscallNumber::SchedGetparam
        | SyscallNumber::SchedSetscheduler
        | SyscallNumber::SchedGetscheduler
        | SyscallNumber::SchedGetPriorityMax
        | SyscallNumber::SchedGetPriorityMin
        | SyscallNumber::SchedRrGetInterval
        | SyscallNumber::SchedSetaffinity
        | SyscallNumber::SchedGetaffinity
        | SyscallNumber::SchedSetattr
        | SyscallNumber::SchedGetattr
        | SyscallNumber::Getpriority
        | SyscallNumber::Setpriority
        | SyscallNumber::IoprioSet
        | SyscallNumber::IoprioGet
        | SyscallNumber::ModifyLdt
        | SyscallNumber::GetThreadArea
        | SyscallNumber::SetThreadArea
        | SyscallNumber::GetRobustList
        | SyscallNumber::SetRobustList
        | SyscallNumber::Personality
        | SyscallNumber::Rseq
        | SyscallNumber::CapDrop => caps.is_valid(),

        SyscallNumber::Getpid => caps.can_getpid(),

        SyscallNumber::Setuid
        | SyscallNumber::Setgid
        | SyscallNumber::Setreuid
        | SyscallNumber::Setregid
        | SyscallNumber::Setresuid
        | SyscallNumber::Setresgid
        | SyscallNumber::Setgroups
        | SyscallNumber::Setfsuid
        | SyscallNumber::Setfsgid
        | SyscallNumber::Seccomp
        | SyscallNumber::Setns
        | SyscallNumber::Unshare => caps.can_admin(),

        _ => return None,
    })
}
