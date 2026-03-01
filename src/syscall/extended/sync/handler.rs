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

use super::constants::*;
use super::wait_wake::{handle_futex_wait, handle_futex_wake};
use super::requeue::{handle_futex_requeue, handle_futex_wake_op};
use super::pi::*;
use crate::syscall::SyscallResult;
use super::super::errno;

pub fn handle_futex(uaddr: u64, futex_op: i32, val: u64, timeout: u64, uaddr2: u64, val3: u64) -> SyscallResult {
    if uaddr == 0 || (uaddr & 3) != 0 {
        return errno(14);
    }

    let op = futex_op & 0x7F;

    match op {
        FUTEX_WAIT => handle_futex_wait(uaddr, val, timeout, FUTEX_BITSET_MATCH_ANY, false),
        FUTEX_WAKE => handle_futex_wake(uaddr, val, FUTEX_BITSET_MATCH_ANY),
        FUTEX_FD => errno(38),
        FUTEX_REQUEUE => handle_futex_requeue(uaddr, val, timeout, uaddr2, 0, false),
        FUTEX_CMP_REQUEUE => handle_futex_requeue(uaddr, val, timeout, uaddr2, val3, true),
        FUTEX_WAKE_OP => handle_futex_wake_op(uaddr, val, uaddr2, timeout, val3),
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 => handle_futex_lock_pi(uaddr, timeout),
        FUTEX_UNLOCK_PI => handle_futex_unlock_pi(uaddr),
        FUTEX_TRYLOCK_PI => handle_futex_trylock_pi(uaddr),
        FUTEX_WAIT_BITSET => handle_futex_wait(uaddr, val, timeout, val3 as u32, false),
        FUTEX_WAKE_BITSET => handle_futex_wake(uaddr, val, val3 as u32),
        FUTEX_WAIT_REQUEUE_PI => handle_futex_wait_requeue_pi(uaddr, val, timeout, uaddr2, val3),
        FUTEX_CMP_REQUEUE_PI => handle_futex_cmp_requeue_pi(uaddr, val, timeout, uaddr2, val3),
        _ => errno(38),
    }
}
