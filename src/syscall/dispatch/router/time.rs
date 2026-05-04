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

use crate::syscall::dispatch::util::errno;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

pub(super) fn dispatch_time(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    _a4: u64,
    _a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Uname => crate::syscall::extended::handle_uname(a0),
        SyscallNumber::Gettimeofday => crate::syscall::extended::handle_gettimeofday(a0, a1),
        SyscallNumber::Settimeofday => crate::syscall::extended::handle_settimeofday(a0, a1),
        SyscallNumber::ClockGettime => {
            crate::syscall::extended::timer::handle_clock_gettime(a0 as i32, a1)
        }
        SyscallNumber::ClockSettime => {
            crate::syscall::extended::timer::handle_clock_settime(a0 as i32, a1)
        }
        SyscallNumber::ClockGetres => {
            crate::syscall::extended::timer::handle_clock_getres(a0 as i32, a1)
        }
        SyscallNumber::Getrusage => crate::syscall::extended::misc::handle_getrusage(a0, a1),
        SyscallNumber::Times => crate::syscall::extended::handle_times(a0),
        // rlimit / sysinfo are Linux POSIX surfaces with no microkernel
        // role. Numbers retained for `from_u64` totality; ENOSYS at
        // dispatch, deny at gate.
        SyscallNumber::Getrlimit
        | SyscallNumber::Setrlimit
        | SyscallNumber::Prlimit64
        | SyscallNumber::Sysinfo => errno(38),
        SyscallNumber::Alarm => crate::syscall::extended::handle_alarm(a0 as u32),
        SyscallNumber::Getitimer => crate::syscall::extended::handle_getitimer(a0 as i32, a1),
        SyscallNumber::Setitimer => crate::syscall::extended::handle_setitimer(a0 as i32, a1, a2),
        SyscallNumber::TimerCreate => crate::syscall::extended::handle_timer_create(a0, a1, a2),
        SyscallNumber::TimerSettime => {
            crate::syscall::extended::handle_timer_settime(a0 as i32, a1 as i32, a2, a3)
        }
        SyscallNumber::TimerGettime => {
            crate::syscall::extended::handle_timer_gettime(a0 as i32, a1)
        }
        SyscallNumber::TimerGetoverrun => {
            crate::syscall::extended::handle_timer_getoverrun(a0 as i32)
        }
        SyscallNumber::TimerDelete => crate::syscall::extended::handle_timer_delete(a0 as i32),
        SyscallNumber::TimerfdCreate => {
            crate::syscall::extended::handle_timerfd_create(a0 as i32, a1 as i32)
        }
        SyscallNumber::TimerfdSettime => {
            crate::syscall::extended::handle_timerfd_settime(a0 as i32, a1 as i32, a2, a3)
        }
        SyscallNumber::TimerfdGettime => {
            crate::syscall::extended::handle_timerfd_gettime(a0 as i32, a1)
        }
        SyscallNumber::Utime => crate::syscall::extended::handle_utime(a0, a1),
        SyscallNumber::Utimes => crate::syscall::extended::handle_utimes(a0, a1),
        SyscallNumber::Utimensat => {
            crate::syscall::extended::handle_utimensat(a0 as i32, a1, a2, a3 as i32)
        }
        SyscallNumber::Futimesat => crate::syscall::extended::handle_futimesat(a0 as i32, a1, a2),
        _ => errno(38),
    }
}
