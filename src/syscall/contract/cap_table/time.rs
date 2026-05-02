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
        SyscallNumber::Uname
        | SyscallNumber::Gettimeofday
        | SyscallNumber::Settimeofday
        | SyscallNumber::ClockGettime
        | SyscallNumber::ClockSettime
        | SyscallNumber::ClockGetres
        | SyscallNumber::Getrusage
        | SyscallNumber::Times
        | SyscallNumber::Getrlimit
        | SyscallNumber::Setrlimit
        | SyscallNumber::Prlimit64
        | SyscallNumber::Sysinfo
        | SyscallNumber::Getcpu
        | SyscallNumber::Alarm
        | SyscallNumber::Getitimer
        | SyscallNumber::Setitimer
        | SyscallNumber::TimerCreate
        | SyscallNumber::TimerSettime
        | SyscallNumber::TimerGettime
        | SyscallNumber::TimerGetoverrun
        | SyscallNumber::TimerDelete
        | SyscallNumber::TimerfdCreate
        | SyscallNumber::TimerfdSettime
        | SyscallNumber::TimerfdGettime
        | SyscallNumber::Time => caps.is_valid(),

        SyscallNumber::Syslog
        | SyscallNumber::Sethostname
        | SyscallNumber::Setdomainname
        | SyscallNumber::Adjtimex
        | SyscallNumber::ClockAdjtime => caps.can_admin(),

        _ => return None,
    })
}
