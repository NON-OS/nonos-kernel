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

use crate::syscall::dispatch::network::*;
use crate::syscall::dispatch::util::errno;
use crate::syscall::numbers::SyscallNumber;
use crate::syscall::SyscallResult;

pub(super) fn dispatch_network(
    syscall: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    _a5: u64,
) -> SyscallResult {
    match syscall {
        SyscallNumber::Socket => handle_socket(a0, a1, a2),
        SyscallNumber::Connect => handle_connect(a0, a1, a2, a3),
        SyscallNumber::Accept => handle_accept(a0, a1, a2),
        SyscallNumber::Accept4 => handle_accept4(a0, a1, a2, a3 as i32),
        SyscallNumber::Sendto => handle_sendto(a0, a1, a2, a3),
        SyscallNumber::Recvfrom => handle_recvfrom(a0, a1, a2, a3),
        SyscallNumber::Sendmsg => handle_sendmsg(a0, a1, a2),
        SyscallNumber::Recvmsg => handle_recvmsg(a0, a1, a2),
        SyscallNumber::Sendmmsg => handle_sendmmsg(a0, a1, a2, a3),
        SyscallNumber::Recvmmsg => handle_recvmmsg(a0, a1, a2, a3, a4),
        SyscallNumber::Shutdown => handle_shutdown(a0 as i32, a1 as i32),
        SyscallNumber::Bind => handle_bind(a0, a1, a2),
        SyscallNumber::Listen => handle_listen(a0, a1),
        SyscallNumber::Getsockname => handle_getsockname(a0, a1, a2),
        SyscallNumber::Getpeername => handle_getpeername(a0, a1, a2),
        SyscallNumber::Socketpair => handle_socketpair(a0, a1, a2, a3),
        SyscallNumber::Setsockopt => handle_setsockopt(a0, a1, a2, a3, a4),
        SyscallNumber::Getsockopt => handle_getsockopt(a0, a1, a2, a3, a4),
        // SysV IPC has no place in the microkernel ABI. The numbers
        // are kept for `from_u64` totality; dispatch ENOSYS, gate denies.
        SyscallNumber::Shmget
        | SyscallNumber::Shmat
        | SyscallNumber::Shmdt
        | SyscallNumber::Shmctl
        | SyscallNumber::Semget
        | SyscallNumber::Semop
        | SyscallNumber::Semctl
        | SyscallNumber::Semtimedop
        | SyscallNumber::Msgget
        | SyscallNumber::Msgsnd
        | SyscallNumber::Msgrcv
        | SyscallNumber::Msgctl => errno(38),
        _ => errno(38),
    }
}
