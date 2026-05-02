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

pub(super) fn dispatch_signal(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    _a4: u64,
    _a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::RtSigaction => crate::syscall::signals::handle_rt_sigaction(a0, a1, a2, a3),
        SyscallNumber::RtSigprocmask => {
            crate::syscall::signals::handle_rt_sigprocmask(a0, a1, a2, a3)
        }
        SyscallNumber::RtSigreturn => crate::syscall::signals::handle_rt_sigreturn(),
        SyscallNumber::RtSigsuspend => crate::syscall::signals::handle_rt_sigsuspend(a0, a1),
        SyscallNumber::RtSigpending => crate::syscall::signals::handle_rt_sigpending(a0, a1),
        SyscallNumber::RtSigqueueinfo => {
            crate::syscall::signals::handle_rt_sigqueueinfo(a0, a1, a2)
        }
        SyscallNumber::Kill => crate::syscall::signals::handle_kill(a0 as i64, a1),
        SyscallNumber::Tkill => crate::syscall::signals::handle_tkill(a0, a1),
        SyscallNumber::Tgkill => crate::syscall::signals::handle_tgkill(a0, a1, a2),
        SyscallNumber::Pause => crate::syscall::signals::handle_pause(),
        SyscallNumber::Signalfd => crate::syscall::extended::handle_signalfd(a0 as i32, a1, a2),
        SyscallNumber::Signalfd4 => {
            crate::syscall::extended::handle_signalfd4(a0 as i32, a1, a2, a3 as i32)
        }
        _ => errno(38),
    }
}
