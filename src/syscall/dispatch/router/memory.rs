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
        SyscallNumber::Mprotect => crate::syscall::extended::handle_mprotect(a0, a1, a2),
        SyscallNumber::Munmap => handle_munmap(a0, a1),
        SyscallNumber::Brk => crate::syscall::extended::handle_brk(a0),
        SyscallNumber::Mremap => crate::syscall::extended::handle_mremap(a0, a1, a2, a3),
        SyscallNumber::Msync => crate::syscall::extended::handle_msync(a0, a1, a2 as i32),
        SyscallNumber::Mincore => crate::syscall::extended::handle_mincore(a0, a1, a2),
        SyscallNumber::Madvise => crate::syscall::extended::handle_madvise(a0, a1, a2 as i32),
        SyscallNumber::Mlock => crate::syscall::extended::handle_mlock(a0, a1),
        SyscallNumber::Mlock2 => crate::syscall::extended::handle_mlock2(a0, a1, a2 as i32),
        SyscallNumber::Munlock => crate::syscall::extended::handle_munlock(a0, a1),
        SyscallNumber::Mlockall => crate::syscall::extended::handle_mlockall(a0 as i32),
        SyscallNumber::Munlockall => crate::syscall::extended::handle_munlockall(),
        SyscallNumber::MemfdCreate => crate::syscall::extended::handle_memfd_create(a0, a1 as u32),
        _ => errno(38),
    }
}
