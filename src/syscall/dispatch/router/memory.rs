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

use crate::syscall::dispatch::file_io::{handle_mmap, handle_munmap};
use crate::syscall::dispatch::util::errno;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

pub(super) fn dispatch_memory(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    _a4: u64,
    _a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Mmap => handle_mmap(a0, a1, a2, a3),
        SyscallNumber::Munmap => handle_munmap(a0, a1),
        // Linux POSIX memory-management surfaces have no microkernel
        // role. Userland mmaps via `mk_mmap` (4 KiB anon) and capsule
        // exit reclaims everything; mprotect/madvise/mlock/memfd are
        // not exposed. ENOSYS at dispatch; gate denies upstream.
        SyscallNumber::Brk
        | SyscallNumber::Mremap
        | SyscallNumber::Mprotect
        | SyscallNumber::Msync
        | SyscallNumber::Mincore
        | SyscallNumber::Madvise
        | SyscallNumber::Mlock
        | SyscallNumber::Mlock2
        | SyscallNumber::Munlock
        | SyscallNumber::Mlockall
        | SyscallNumber::Munlockall
        | SyscallNumber::MemfdCreate => errno(38),
        _ => errno(38),
    }
}
