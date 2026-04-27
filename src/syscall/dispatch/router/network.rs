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
        SyscallNumber::Shmget => crate::syscall::extended::handle_shmget(a0, a1, a2 as i32),
        SyscallNumber::Shmat => crate::syscall::extended::handle_shmat(a0 as i32, a1, a2 as i32),
        SyscallNumber::Shmdt => crate::syscall::extended::handle_shmdt(a0),
        SyscallNumber::Shmctl => crate::syscall::extended::handle_shmctl(a0 as i32, a1 as i32, a2),
        SyscallNumber::Semget => crate::syscall::extended::handle_semget(a0, a1 as i32, a2 as i32),
        SyscallNumber::Semop => crate::syscall::extended::handle_semop(a0 as i32, a1, a2),
        SyscallNumber::Semctl => {
            crate::syscall::extended::handle_semctl(a0 as i32, a1 as i32, a2 as i32, a3)
        }
        SyscallNumber::Semtimedop => {
            crate::syscall::extended::handle_semtimedop(a0 as i32, a1, a2, a3)
        }
        SyscallNumber::Msgget => crate::syscall::extended::handle_msgget(a0, a1 as i32),
        SyscallNumber::Msgsnd => {
            crate::syscall::extended::handle_msgsnd(a0 as i32, a1, a2, a3 as i32)
        }
        SyscallNumber::Msgrcv => {
            crate::syscall::extended::handle_msgrcv(a0 as i32, a1, a2, a3 as i64, a4 as i32)
        }
        SyscallNumber::Msgctl => crate::syscall::extended::handle_msgctl(a0 as i32, a1 as i32, a2),
        _ => errno(38),
    }
}
