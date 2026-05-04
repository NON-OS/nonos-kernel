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
        // Microkernel ABI memory surface: only mmap is admitted.
        // Linux POSIX adjuncts (mprotect/madvise/mlock/memfd/etc.)
        // are deleted at dispatch and stripped from the cap table so
        // the gate denies them with EPERM.
        SyscallNumber::Mmap => caps.can_allocate_memory(),

        SyscallNumber::Munmap => caps.can_deallocate_memory(),

        SyscallNumber::ProcessVmReadv | SyscallNumber::ProcessVmWritev => caps.can_admin(),

        _ => return None,
    })
}
