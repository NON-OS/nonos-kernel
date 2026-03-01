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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::constants::FUTEX_BITSET_MATCH_ANY;
use super::helpers::{wake_futex, decode_wake_op, apply_wake_op, eval_wake_op_cmp};
use super::types::{ok, FUTEX_WAITER_MAP, FUTEX_WAKES};
use crate::syscall::SyscallResult;
use super::super::errno;

pub(super) fn handle_futex_requeue(uaddr: u64, val: u64, val2: u64, uaddr2: u64, val3: u64, cmp: bool) -> SyscallResult {
    if uaddr2 == 0 || (uaddr2 & 3) != 0 {
        return errno(14);
    }

    if cmp {
        // SAFETY: Reading current value for comparison
        let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
        if current != val3 as u32 {
            return errno(11);
        }
    }

    let max_wake = val as usize;
    let max_requeue = val2 as usize;

    let mut woken = 0;
    let mut requeued = 0;

    let mut waiters_guard = FUTEX_WAITER_MAP.lock();

    let mut pids_to_requeue = Vec::new();

    if let Some(waiters) = waiters_guard.get_mut(&uaddr) {
        while woken < max_wake && !waiters.is_empty() {
            waiters.remove(0);
            woken += 1;
        }

        while requeued < max_requeue && !waiters.is_empty() {
            pids_to_requeue.push(waiters.remove(0));
            requeued += 1;
        }
    }

    for waiter in pids_to_requeue {
        waiters_guard.entry(uaddr2).or_insert_with(Vec::new).push(waiter);
    }

    FUTEX_WAKES.fetch_add(woken as u64, Ordering::Relaxed);
    ok(woken as i64)
}

pub(super) fn handle_futex_wake_op(uaddr: u64, val: u64, uaddr2: u64, val2: u64, val3: u64) -> SyscallResult {
    if uaddr2 == 0 || (uaddr2 & 3) != 0 {
        return errno(14);
    }

    let (op, oparg, cmp, cmparg, _shift) = decode_wake_op(val3);

    let old_val = apply_wake_op(uaddr2, op, oparg);

    let woken1 = wake_futex(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);

    let woken2 = if eval_wake_op_cmp(cmp, old_val, cmparg) {
        wake_futex(uaddr2, val2 as usize, FUTEX_BITSET_MATCH_ANY)
    } else {
        0
    };

    ok((woken1 + woken2) as i64)
}
