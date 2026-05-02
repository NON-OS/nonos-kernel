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
        SyscallNumber::EpollCreate
        | SyscallNumber::EpollCreate1
        | SyscallNumber::EpollCtl
        | SyscallNumber::EpollCtlOld
        | SyscallNumber::EpollWait
        | SyscallNumber::EpollWaitOld
        | SyscallNumber::EpollPwait
        | SyscallNumber::Eventfd
        | SyscallNumber::Eventfd2
        | SyscallNumber::InotifyInit
        | SyscallNumber::InotifyInit1
        | SyscallNumber::InotifyAddWatch
        | SyscallNumber::InotifyRmWatch => caps.is_valid(),

        _ => return None,
    })
}
